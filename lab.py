"""Prepare and explicitly approve a one-hour charter for the bundled local lab."""
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


def approve(folder, operator):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,127}", operator):
        raise ValueError("Use an operator ID of 1 to 128 letters, digits or ._@-")
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
    authorization = (f"Local lab approval by {operator}. One anonymous GET of the bundled Juice Shop "
                     f"landing page per capture. No other targets or paths. Valid {start} through {end}.\n")
    document = bundle / "authorization.txt"
    document.write_bytes(authorization.encode("utf-8"))
    record = dict(engagement="juice-shop-" + name[:8], operator=operator, approver="lab-owner",
                  starts_at=start, ends_at=end, authorization_sha256=sha256(document.read_bytes()).hexdigest(),
                  allow=[TARGET], deny=[TARGET + "private"])
    charter = bundle / "charter.json"
    charter.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", "charter-scope-v1", str(charter)], check=True)
    subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(trust), "-I", "lab-owner",
                    "-n", "charter-scope-v1", "-s", str(charter) + ".sig"], input=charter.read_bytes(), check=True)
    env = folder / "compose.env"
    if not env.exists():
        with env.open("x", encoding="ascii") as file:
            file.write("CHARTER_DB_PASSWORD=" + secrets.token_urlsafe(36) + "\n")
    pointer = approved / (name + ".tmp")
    pointer.write_text(name, encoding="ascii")
    os.replace(pointer, approved / "current")
    print(f"Approved {record['engagement']} until {end}.")
    return charter


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--approve-local-lab", required=True, action="store_true",
                        help="Confirm you control this local lab and approve its single read-only check")
    args = parser.parse_args()
    approve(Path(__file__).resolve().parent / "private", args.operator)
