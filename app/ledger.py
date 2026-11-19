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


def _key(url):
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return ""
    return f"{parts.scheme}://{parts.netloc}{parts.path or '/'}"


class Ledger:
    def __init__(self):
        self.endpoints = {}
        self.attempts = {}
        self.fetched = set()
        self.queue = []
        self.recon_turns = 0
        self.mapped = False
        self.pipeline_done = False

    def _row(self, url):
        key = _key(url)
        if not key:
            return None
        parts = urlsplit(key)
        return self.endpoints.setdefault(key, {
            "url": key, "path": parts.path or "/", "params": [], "forms": [], "sample": "",
        })

    def _add_param(self, row, name):
        if row is None or len(row["params"]) >= 12:
            return
        if re.fullmatch(r"[A-Za-z0-9_-]{1,40}", name) and name not in row["params"]:
            row["params"].append(name)

    def record_url(self, url):
        """Remember a same-origin URL and its query names before it is fetched again."""
        row = self._row(url)
        if row is None:
            return
        for name, _value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            self._add_param(row, name)
        if row["params"] and not row["sample"]:
            row["sample"] = url.split("#", 1)[0]

    def observe(self, exchange):
        if exchange is None or exchange.blocked or exchange.skipped or not exchange.url:
            return
        key = _key(exchange.url)
        if not key:
            return
        self.fetched.add(key)
        self.record_url(exchange.url)
        row = self.endpoints[key]
        for form in _forms(exchange.body or ""):
            action = urljoin(exchange.url, form.get("action") or exchange.url)
            if not _same_host(exchange.url, action):
                continue
            fields = [field for field in form.get("fields") or [] if field.get("name")][:8]
            method = form.get("method") or "GET"
            if method == "GET":
                target = self._row(action)
                for field in fields:
                    self._add_param(target, field["name"])
                if target is not None and target["params"] and not target["sample"]:
                    target["sample"] = action.split("#", 1)[0].split("?", 1)[0]
                self._enqueue(action)
                continue
            compact = {"method": method, "action": action.split("#", 1)[0], "fields": fields}
            if compact not in row["forms"] and len(row["forms"]) < 4:
                row["forms"].append(compact)
        try:
            from .workers import page_links
        except Exception:
            return
        for link in page_links(exchange.url, exchange.body or ""):
            self.record_url(link)
            self._enqueue(link)

    def _enqueue(self, url):
        key = _key(url)
        if not key or key in self.fetched or url in self.queue or len(self.queue) >= 80:
            return
        self.queue.append(url.split("#", 1)[0])

    def pending(self):
        fresh = []
        for url in self.queue:
            key = _key(url)
            if key and key not in self.fetched and url not in fresh:
                fresh.append(url)
        fresh.sort(key=lambda url: 0 if urlsplit(url).query else 1)
        return fresh

    def mark(self, path, check, outcome):
        self.attempts[(str(path or ""), str(check or ""))] = str(outcome or "checked")

    def attempted(self, path, check):
        return (str(path or ""), str(check or "")) in self.attempts

    def seen_check(self, check):
        ident = str(check or "")
        return any(name == ident for (_path, name) in self.attempts)

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
