"""List or decide steps that are waiting outside lab mode."""
import argparse
import json
import sys

from . import storage


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["list", "approve", "deny"])
    parser.add_argument("approval_id", nargs="?")
    args = parser.parse_args()
    storage.initialize()
    if args.action == "list":
        for row in storage.pending_approvals():
            print(row["id"], json.dumps(row["task"], default=str))
        return 0
    if not args.approval_id:
        print("An approval id is required.", file=sys.stderr)
        return 1
    state = "approved" if args.action == "approve" else "denied"
    ok = storage.decide_approval(args.approval_id, state)
    print(state if ok else "not pending")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
