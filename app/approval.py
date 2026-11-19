"""Per-step approval outside lab mode. Lab mode does not call this queue."""
import json
from time import monotonic, sleep

from .framing import preview


def public_task(task):
    shown = {}
    for key in ("worker", "intent", "method", "url", "check"):
        if task.get(key) not in (None, ""):
            shown[key] = task[key]
    if task.get("use_session"):
        shown["use_session"] = True
    body = task.get("body")
    if body is not None:
        text = body if isinstance(body, str) else json.dumps(body)
        shown["body"] = preview(text, 300)
    return shown


class Queue:
    def __init__(self, store, timeout=3600, sleep_fn=None, monotonic_fn=None):
        self.store = store
        self.timeout = timeout
        self.sleep = sleep_fn or sleep
        self.monotonic = monotonic_fn or monotonic

    def require(self, campaign_id, task):
        approval_id = self.store.create_approval(campaign_id, public_task(task))
        deadline = self.monotonic() + self.timeout
        while self.monotonic() < deadline:
            state = self.store.approval_state(approval_id)
            if state in {"approved", "denied"}:
                return state
            self.sleep(0.5)
        self.store.decide_approval(approval_id, "denied")
        return "denied"
