"""Request one in-scope URL through the capture service.

With no --url, the target is the signed charter's first allow rule. The bundled
Juice Shop lab is used only when that charter is not mounted.
"""
import argparse
import os
import sys
import httpx

from .loop import default_target
from .scope_gate import load_verified
from .worker_config import TARGET

PROXY = os.environ.get("CHARTER_PROXY", "http://capture:8080")


def denial_url(url):
    root = os.environ.get("CHARTER_ROOT", "/run/charter")
    try:
        charter = load_verified(root)
        if charter.get("deny"):
            return charter["deny"][0]
    except Exception:
        pass
    return url + "private" if url.endswith("/") else url + "/private"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", help="In-scope URL to request. Defaults to the charter's first allow rule.")
    parser.add_argument("--check-denial", action="store_true", help="Exercise a signed deny rule")
    args = parser.parse_args()
    root = os.environ.get("CHARTER_ROOT", "/run/charter")
    url = args.url or default_target(root, TARGET)
    if args.check_denial:
        url = denial_url(args.url or default_target(root, TARGET))
    with httpx.Client(proxy=PROXY, trust_env=False, follow_redirects=False, timeout=20) as client:
        response = client.get(url, headers={"Accept-Encoding": "identity", "Accept": "text/html"})
    print(f"HTTP {response.status_code}  Run {response.headers.get('X-Charter-Run', 'unavailable')}")
    if args.check_denial:
        return int(response.status_code != 403 or "X-Charter-Run" not in response.headers)
    return int(response.status_code != 200 or "X-Charter-Run" not in response.headers)


if __name__ == "__main__":
    sys.exit(main())
