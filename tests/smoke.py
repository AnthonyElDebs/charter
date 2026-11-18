"""Run on a local Compose host after approving a lab charter and starting the services."""
import argparse
import base64
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import time
from urllib.request import urlopen
from uuid import UUID


COMPOSE = ["docker", "compose", "--env-file", "private/compose.env"]
BASE = "http://127.0.0.1:8000"


def worker(*extra):
    process = subprocess.run([*COMPOSE, "run", "--rm", "worker", "python", "-m", "app.worker", *extra],
                             capture_output=True, text=True, timeout=120)
    if process.returncode:
        raise RuntimeError(process.stdout + process.stderr)
    return UUID(process.stdout.strip().splitlines()[-1].split()[-1])


def get(path):
    with urlopen(BASE + path, timeout=15) as response:
        return response.read()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export", type=Path, help="Save the verified local demo reports in this directory")
    args = parser.parse_args()
    # Juice Shop can still be initializing when Docker reports that its process has started.
    for attempt in range(10):
        try:
            run_id = worker()
            break
        except RuntimeError:
            if attempt == 9:
                raise
            time.sleep(3)
    denied = worker("--check-denial")
    run = json.loads(get(f"/api/runs/{run_id}"))
    block = json.loads(get(f"/api/runs/{denied}"))
    assert block["state"] == "blocked" and block["evidence"] is None
    assert run["state"] == "complete" and run["evidence"]["response"]["status"] == 200
    assert run["finding"] and "Content-Security-Policy" in run["finding"]["title"]
    assert run["evidence"]["request"]["url"] == "http://juice-shop:3000/"
    for msg in run["evidence"].values():
        body = base64.b64decode(msg["body_base64"], validate=True)
        assert len(body) == msg["body_bytes"] and sha256(body).hexdigest() == msg["body_sha256"]
    html = get(f"/runs/{run_id}/report.html")
    pdf = get(f"/runs/{run_id}/report.pdf")
    assert b"Complete body in base64" in html and pdf.startswith(b"%PDF-")
    assert str(run_id).encode() in get("/")
    if args.export:
        args.export.mkdir(parents=True, exist_ok=True)
        (args.export / "engagement.html").write_bytes(html)
        (args.export / "engagement.pdf").write_bytes(pdf)
    print(f"PASS: captured {run_id}, blocked {denied}, confirmed finding, verified both reports.")


if __name__ == "__main__":
    main()
