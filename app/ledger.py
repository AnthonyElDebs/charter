"""What this campaign has already seen and already tried.

The planner receives this every turn. Recon and coverage use it so a check is not repeated.
"""
import re
from urllib.parse import parse_qsl, urljoin, urlsplit

from .coverage import _forms


def _same_host(page, link):
    left, right = urlsplit(page), urlsplit(link)
    if left.scheme not in {"http", "https"} or right.scheme not in {"http", "https"}:
        return False
    return (left.hostname or "").lower() == (right.hostname or "").lower()


class Ledger:
    def __init__(self):
        self.endpoints = {}
        self.attempts = {}
        self.recon_turns = 0
        self.mapped = False
        self.pipeline_done = False

    def observe(self, exchange):
        if exchange is None or exchange.blocked or exchange.skipped or not exchange.url:
            return
        parts = urlsplit(exchange.url)
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            return
        path = parts.path or "/"
        key = f"{parts.scheme}://{parts.netloc}{path}"
        row = self.endpoints.setdefault(key, {"url": key, "path": path, "params": [], "forms": [], "sample": ""})
        for name, _value in parse_qsl(parts.query, keep_blank_values=True):
            if re.fullmatch(r"[A-Za-z0-9_-]{1,40}", name) and name not in row["params"]:
                row["params"].append(name)
        if row["params"] and not row["sample"]:
            row["sample"] = exchange.url.split("#", 1)[0]
        for form in _forms(exchange.body or ""):
            action = urljoin(exchange.url, form.get("action") or exchange.url)
            if not _same_host(exchange.url, action):
                continue
            compact = {"method": form.get("method") or "GET", "action": action.split("#", 1)[0],
                       "fields": [field for field in form.get("fields") or [] if field.get("name")][:8]}
            if compact not in row["forms"] and len(row["forms"]) < 4:
                row["forms"].append(compact)

    def mark(self, path, check, outcome):
        self.attempts[(str(path or ""), str(check or ""))] = str(outcome or "checked")

    def attempted(self, path, check):
        return (str(path or ""), str(check or "")) in self.attempts

    def snapshot(self):
        endpoints = []
        for row in list(self.endpoints.values())[:30]:
            endpoints.append({
                "path": row["path"],
                "params": row["params"][:8],
                "forms": [{"method": form["method"], "action": urlsplit(form["action"]).path or "/",
                           "fields": [field.get("name") for field in form["fields"]]} for form in row["forms"]],
            })
        attempts = [f"{path} {check} {outcome}" for (path, check), outcome in list(self.attempts.items())[:40]]
        return {"mapped": self.mapped, "recon_turns": self.recon_turns,
                "pipeline_done": self.pipeline_done, "endpoints": endpoints, "attempts": attempts}
