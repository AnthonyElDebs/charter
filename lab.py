"""Approve a one-hour charter for the bundled lab or for an origin you are authorized to test."""
import argparse
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
from uuid import uuid4

from app.worker_config import TARGET


def ensure_database_password(env):
    """Add a database password without touching model settings already in the file."""
    secret = secrets.token_urlsafe(36)
    if not env.exists():
        env.write_text("CHARTER_DB_PASSWORD=" + secret + "\n", encoding="ascii")
        return
    lines = env.read_text(encoding="utf-8").splitlines()
    found = False
    output = []
    for line in lines:
        if line.startswith("CHARTER_DB_PASSWORD="):
            value = line.split("=", 1)[1].strip()
            output.append(line if value else "CHARTER_DB_PASSWORD=" + secret)
            found = True
        else:
            output.append(line)
    if not found:
        output.append("CHARTER_DB_PASSWORD=" + secret)
    env.write_text("\n".join(output) + "\n", encoding="utf-8")


def approve(folder, operator, target=None):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,127}", operator):
        raise ValueError("Use an operator ID of 1 to 128 letters, digits or ._@-")
    target = target or TARGET
    from charter import scope_url, Refused
    try:
        scope_url(target, rule=True)
    except Refused as exc:
        raise ValueError("target must be an http(s) origin without a query or fragment") from exc
    folder.mkdir(mode=0o700, exist_ok=True)
    approved = folder / "approved"
    approved.mkdir(exist_ok=True)
    key = folder / "lab-owner.key"
    if not key.exists():
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    pubkey = Path(str(key) + ".pub").read_text(encoding="ascii").strip()
    # Trust is enrolled once. Never silently replace the trusted signer during renewal.
    trust = approved / "signers"
    if not trust.exists():
        with trust.open("x", encoding="ascii") as file:
            file.write("lab-owner " + pubkey + "\n")
    name = uuid4().hex
    bundle = approved / name
    bundle.mkdir()
    now = datetime.now(timezone.utc)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    start, end = now.strftime(fmt), (now + timedelta(hours=1)).strftime(fmt)
    if target == TARGET:
        authorization = (f"Local lab approval by {operator}. Authorized testing of the bundled Juice Shop "
                         f"origin except the denied /private prefix. Valid {start} through {end}.\n")
        deny = [TARGET + "private"]
        engagement = "juice-shop-" + name[:8]
    else:
        authorization = (f"Approval by {operator} for authorized testing of {target}. "
                         f"Other origins are out of scope. Valid {start} through {end}.\n")
        deny = []
        engagement = "scope-" + name[:8]
    document = bundle / "authorization.txt"
    document.write_bytes(authorization.encode("utf-8"))
    record = dict(engagement=engagement, operator=operator, approver="lab-owner",
                  starts_at=start, ends_at=end, authorization_sha256=sha256(document.read_bytes()).hexdigest(),
                  allow=[target], deny=deny)
    charter = bundle / "charter.json"
    charter.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", "charter-scope-v1", str(charter)], check=True)
    subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(trust), "-I", "lab-owner",
                    "-n", "charter-scope-v1", "-s", str(charter) + ".sig"], input=charter.read_bytes(), check=True)
    ensure_database_password(folder / "compose.env")
    pointer = approved / (name + ".tmp")
    pointer.write_text(name, encoding="ascii")
    os.replace(pointer, approved / "current")
    print(f"Approved {record['engagement']} until {end}.")
    return charter


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--target", help="Origin you are authorized to test. Defaults to the bundled Juice Shop lab.")
    parser.add_argument("--approve-local-lab", action="store_true",
                        help="Confirm you control this machine's Juice Shop lab")
    parser.add_argument("--approve-target", action="store_true",
                        help="Confirm you are authorized to test --target")
    args = parser.parse_args()
    target = args.target or TARGET
    if target == TARGET and not (args.approve_local_lab or args.approve_target):
        parser.error("Pass --approve-local-lab for the bundled lab")
    if target != TARGET and not args.approve_target:
        parser.error("Pass --approve-target to authorize an origin you control")
    approve(Path(__file__).resolve().parent / "private", args.operator, target)
