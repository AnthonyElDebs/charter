"""Run one authorized campaign from a goal and a target URL."""
import argparse
import os
from pathlib import Path
import sys

from charter import Refused
from . import storage
from .llm import Llm, LlmError
from .loop import resolve_lab_mode, run_campaign
from .scope_gate import load_verified, local_charter
from .worker_config import TARGET


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--goal", default=os.environ.get("CHARTER_GOAL", ""))
    parser.add_argument("--url", default=os.environ.get("CHARTER_TARGET", ""),
                        help="Main URL to test. It must match the signed charter.")
    parser.add_argument("--lab", action=argparse.BooleanOptionalAction, default=None,
                        help="Skip per-step approval. The charter is still enforced.")
    parser.add_argument("--max-turns", type=int)
    parser.add_argument("--max-requests", type=int)
    args = parser.parse_args()
    goal = (args.goal or "").strip()
    if not goal:
        print("Set --goal or CHARTER_GOAL.", file=sys.stderr)
        return 1
    root = Path(os.environ.get("CHARTER_ROOT", "/run/charter"))
    try:
        charter = load_verified(root)
        storage.initialize()
    except (Refused, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    try:
        llm = Llm.from_env()
    except LlmError as exc:
        llm = None
        print(str(exc) + " Continuing with the deterministic sweep and a templated report.", file=sys.stderr)
    from .governor import Governor
    governor = Governor.from_env()
    if args.max_turns:
        governor.max_turns = args.max_turns
    if args.max_requests:
        governor.max_requests = args.max_requests
    target = args.url.strip() or (charter["allow"][0] if charter.get("allow") else TARGET)
    lab = resolve_lab_mode(args.lab, charter)
    if lab and not local_charter(charter):
        print("Per-step approval is off for this run. The signed charter is still enforced.", file=sys.stderr)
    result = run_campaign(goal, root=root, store=storage, llm=llm, lab=lab, governor=governor,
                          charter=charter, target=target)
    print(f"{result.state} {result.campaign_id}")
    if result.reason:
        print(result.reason)
    for finding in result.findings:
        mark = "proven" if finding.get("proven") else "observed"
        print(f"- {finding['severity']} {finding['title']} ({mark}, run {finding.get('run_id')})")
    return 0 if result.state == "proven" else 1


if __name__ == "__main__":
    sys.exit(main())
