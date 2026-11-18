"""Check a URL against a signed engagement charter without contacting the target."""

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit


class Refused(ValueError):
    pass


def distinct_fields(pairs):
    record = {}
    for key, value in pairs:
        if key in record:
            raise Refused("duplicate JSON field")
        record[key] = value
    return record


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value
    ):
        raise Refused("time must use YYYY-MM-DDTHH:MM:SSZ")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise Refused("invalid calendar time") from exc


def scope_url(value, *, rule=False):
    # Accept a small, literal URL syntax so different path decoders cannot disagree.
    if not isinstance(value, str) or not value.isascii() or any(
        ord(char) <= 32 or ord(char) == 127 or char in "\\#" for char in value
    ):
        raise Refused("invalid URL characters")
    if rule and "?" in value:
        raise Refused("scope rules must omit the query")
    try:
        url = urlsplit(value)
        port = url.port
    except ValueError as exc:
        raise Refused("invalid host or port") from exc
    if url.scheme not in {"http", "https"} or not re.fullmatch(
        r"[a-zA-Z0-9.-]+(?::[0-9]+)?", url.netloc
    ) or port == 0:
        raise Refused("expected an HTTP origin with a literal hostname or IPv4 address")
    path = url.path or "/"
    if not re.fullmatch(r"/[a-zA-Z0-9._~/-]*", path) or "//" in path or any(
        part in {".", ".."} for part in path.split("/")
    ):
        raise Refused("ambiguous or unsupported URL path")
    origin = (url.scheme, url.hostname, port or (443 if url.scheme == "https" else 80))
    return origin, path.rstrip("/")


def matches(candidate, rule):
    origin, path = candidate
    rule_origin, prefix = rule
    return origin == rule_origin and (path == prefix or path.startswith(prefix + "/"))


def check(args, event):
    raw = args.charter.read_bytes()
    event["charter_sha256"] = sha256(raw).hexdigest()
    try:
        charter = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=distinct_fields)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise Refused("invalid charter JSON") from exc
    fields = {"engagement", "operator", "approver", "authorization_sha256",
              "starts_at", "ends_at", "allow", "deny"}
    if not isinstance(charter, dict) or charter.keys() != fields:
        raise Refused("missing or unknown charter field")
    for field in ("engagement", "operator", "approver"):
        if not isinstance(charter[field], str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9@._-]{0,127}", charter[field]
        ):
            raise Refused(f"invalid {field}")
    verified = subprocess.run(
        ["ssh-keygen", "-Y", "verify", "-f", str(args.signers.resolve()),
         "-I", charter["approver"], "-n", "charter-scope-v1", "-s", str(args.signature.resolve())],
        input=raw, capture_output=True, timeout=10, check=False,
    )
    if verified.returncode:
        raise Refused("charter signature or signer trust check failed")
    event["engagement"] = charter["engagement"]
    if sha256(args.authorization.read_bytes()).hexdigest() != charter["authorization_sha256"]:
        raise Refused("authorization document digest mismatch")
    start, end = timestamp(charter["starts_at"]), timestamp(charter["ends_at"])
    if not start <= datetime.now(timezone.utc) < end:
        raise Refused("outside the authorized time window")
    rules = {}
    for field in ("allow", "deny"):
        values = charter[field]
        if not isinstance(values, list):
            raise Refused(f"{field} must be an array of URL rules")
        rules[field] = [scope_url(value, rule=True) for value in values]
    candidate = scope_url(args.url)
    if any(matches(candidate, rule) for rule in rules["deny"]):
        raise Refused("matched a deny rule")
    if not any(matches(candidate, rule) for rule in rules["allow"]):
        raise Refused("no matching allow rule")
    return charter


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="URL to classify offline")
    for name in ("charter", "signature", "signers", "authorization", "audit"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    args = parser.parse_args()
    event = {"time": datetime.now(timezone.utc).isoformat(),
             "url_sha256": sha256(args.url.encode("utf-8")).hexdigest(), "decision": "DENY"}
    try:
        check(args, event)
        event["decision"] = "IN_SCOPE"
    except Refused as exc:
        event["reason"] = str(exc)
    except (OSError, subprocess.SubprocessError, RecursionError) as exc:
        event["reason"] = f"could not read inputs or verify signature ({type(exc).__name__})"
    try:
        with args.audit.open("a", encoding="utf-8") as audit:
            audit.write(json.dumps(event) + "\n")
    except OSError:
        print("DENY - could not write audit record", file=sys.stderr)
        return 1
    print(event["decision"] + (" - " + event["reason"] if "reason" in event else ""))
    return int(event["decision"] != "IN_SCOPE")


if __name__ == "__main__":
    sys.exit(main())
