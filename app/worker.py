"""One anonymous GET, fixed to the lab landing page, through the capture service."""
import argparse
import sys
import httpx

from .worker_config import TARGET
PROXY = "http://capture:8080"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-denial", action="store_true", help="Exercise the signed deny rule")
    args = parser.parse_args()
    with httpx.Client(proxy=PROXY, trust_env=False, follow_redirects=False, timeout=20) as client:
        response = client.get(TARGET + ("private" if args.check_denial else ""),
                              headers={"Accept-Encoding": "identity", "Accept": "text/html"})
    print(f"HTTP {response.status_code}  Run {response.headers.get('X-Charter-Run', 'unavailable')}")
    if args.check_denial:
        return int(response.status_code != 403 or "X-Charter-Run" not in response.headers)
    return int(response.status_code != 200 or "X-Charter-Run" not in response.headers)


if __name__ == "__main__":
    sys.exit(main())
