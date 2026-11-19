"""Send one HTTP request through the capture proxy after the charter accepts it."""
import os
from urllib.parse import urlsplit
import json

import httpx

from charter import Refused, check
from .capture import active_charter
from .framing import preview
from .governor import BudgetExhausted
from .scope_gate import fatal_scope, open_scope, restrictions_open


PROXY = "http://capture:8080"
METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
HEADER_NAMES = {"accept", "content-type", "authorization", "cookie", "origin"}


class Exchange:
    def __init__(self, *, method, url, status=0, body="", run_id=None, blocked=False,
                 skipped=False, reason="", authenticated=False, headers=None):
        self.method = method
        self.url = url
        self.status = status
        self.body = body or ""
        self.run_id = run_id
        self.blocked = blocked
        self.skipped = skipped
        self.reason = reason
        self.authenticated = authenticated
        self.headers = {str(key).lower(): str(value) for key, value in (headers or {}).items()}


def location(url):
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}{parts.path}"


def describe(exchange):
    place = location(exchange.url)
    if exchange.skipped:
        return f"{exchange.method} {place} skipped: {exchange.reason}"
    if exchange.blocked:
        return f"{exchange.method} {place} refused before send: {exchange.reason}"
    return (f"{exchange.method} {place} -> {exchange.status} run={exchange.run_id or 'none'}\n"
            f"preview: {preview(exchange.body)}")


def request_through_proxy(url, method="GET", body=None, headers=None, proxy=None, intent=""):
    """One shot used by the operator console and the phase-1 worker. The proxy enforces scope."""
    proxy = proxy or os.environ.get("CHARTER_PROXY", PROXY)
    outbound = {"Accept-Encoding": "identity",
                "Accept": "text/html,application/json;q=0.9,*/*;q=0.8"}
    if headers:
        outbound.update(headers)
    if intent:
        outbound["X-Charter-Intent"] = "".join(char for char in intent if 32 <= ord(char) < 127)[:160]
    content = body if body else None
    with httpx.Client(proxy=proxy, trust_env=False, follow_redirects=False, timeout=30) as client:
        return client.request(method, url, headers=outbound, content=content)


class Client:
    """Campaign client. Refuses a URL locally, then sends only the ones the charter allows."""

    def __init__(self, *, root, charter, store, governor=None, proxy=None, transport=None,
                 campaign_id=None, target=None):
        self.root = root
        self.charter = charter
        self.store = store
        self.governor = governor
        self.proxy = proxy or os.environ.get("CHARTER_PROXY", PROXY)
        self.campaign_id = campaign_id
        self.target = target
        self.identity = {}
        self.credentials = {}
        self.accounts = []
        self.ledger = None
        self.recent = []
        options = {"trust_env": False, "follow_redirects": False, "timeout": 30}
        if transport is not None:
            self.http = httpx.Client(transport=transport, **options)
        else:
            self.http = httpx.Client(proxy=self.proxy, **options)

    def close(self):
        self.http.close()

    def enforce(self, url):
        if not isinstance(url, str) or len(url) > 2048:
            raise Refused("invalid URL characters")
        if restrictions_open():
            self.charter = open_scope(url)
            return self.charter
        try:
            charter = check(active_charter(self.root, url), {})
        except OSError as exc:
            raise Refused("missing or invalid approval bundle") from exc
        self.charter = charter
        return charter

    def allows(self, url):
        try:
            self.enforce(url)
        except Refused as exc:
            if fatal_scope(str(exc)):
                raise
            return False
        return True

    def keep(self, exchange, finding):
        if not finding or not exchange.run_id or exchange.blocked or exchange.skipped:
            return None
        return self.store.attach_finding(exchange.run_id, finding)

    def send(self, method, url, *, headers=None, body=None, intent="", use_session=False):
        method = (method or "GET").upper()
        if method not in METHODS:
            return self._blocked(method, url, "method is not allowed", intent)
        try:
            clean = self._headers(headers)
            raw = self._body(body, clean)
        except Refused as exc:
            return self._blocked(method, url, str(exc), intent)
        if use_session:
            token = self.identity.get("token")
            cookie = self.identity.get("cookie")
            if not token and not cookie:
                return Exchange(method=method, url=url, skipped=True, blocked=True,
                                reason="no lab session; run auth-setup first")
            if token:
                clean["authorization"] = "Bearer " + token
            if cookie:
                clean["cookie"] = cookie
        try:
            self.enforce(url)
        except Refused as exc:
            self._note(url, str(exc), intent)
            if fatal_scope(str(exc)):
                raise
            return Exchange(method=method, url=url, blocked=True, reason=str(exc))
        if self.governor is not None:
            self.governor.before_request()
        if self.campaign_id:
            clean["X-Charter-Campaign"] = str(self.campaign_id)
        if intent:
            safe = "".join(char for char in intent if 32 <= ord(char) < 127)[:160]
            if safe:
                clean["X-Charter-Intent"] = safe
        authenticated = "authorization" in clean or "cookie" in clean
        try:
            response = self._once(method, url, clean, raw)
            if response.status_code == 403 and response.headers.get("X-Charter-Reason") == "rate-limit":
                if self.governor is not None:
                    self.governor.pause()
                response = self._once(method, url, clean, raw)
        except httpx.HTTPError as exc:
            return Exchange(method=method, url=url, blocked=True, authenticated=authenticated,
                            reason=f"transport {type(exc).__name__}")
        denied = response.status_code == 403 and response.headers.get("X-Charter-Reason") in {"denied", "rate-limit"}
        exchange = Exchange(method=method, url=url, status=response.status_code, body=response.text,
                            run_id=response.headers.get("X-Charter-Run"), blocked=denied,
                            reason=response.headers.get("X-Charter-Reason", ""), authenticated=authenticated,
                            headers=response.headers)
        if not denied:
            self._remember(exchange)
            self.recent.append({"method": method, "url": url, "status": exchange.status,
                                "body": (exchange.body or "")[:500]})
            if len(self.recent) > 12:
                del self.recent[:-12]
            if self.ledger is not None:
                try:
                    self.ledger.observe(exchange)
                except Exception:
                    pass
        return exchange

    def _blocked(self, method, url, reason, intent):
        self._note(url, reason, intent)
        return Exchange(method=method, url=url, blocked=True, reason=reason)

    def _note(self, url, reason, intent):
        if self.store is not None:
            self.store.note_block(self.campaign_id, url, reason, intent)

    def _headers(self, headers):
        clean = {}
        for key, value in (headers or {}).items():
            name = str(key).lower()
            if name not in HEADER_NAMES:
                continue
            text = str(value)
            if any(ord(char) < 32 or ord(char) == 127 for char in text):
                raise Refused("invalid header value")
            clean[name] = text[:4096]
        return clean

    def _body(self, body, headers):
        if body is None:
            return b""
        if isinstance(body, (dict, list)):
            raw = json.dumps(body).encode()
            headers.setdefault("content-type", "application/json")
        elif isinstance(body, str):
            raw = body.encode()
        elif isinstance(body, bytes):
            raw = body
        else:
            raise Refused("invalid body")
        if len(raw) > 262144:
            raise Refused("request body exceeds the local limit")
        return raw

    def _once(self, method, url, headers, raw):
        return self.http.request(method, url, headers=headers, content=raw or None)

    def _remember(self, exchange):
        raw_cookie = exchange.headers.get("set-cookie", "")
        if raw_cookie:
            pair = raw_cookie.split(";", 1)[0].strip()
            if "=" in pair:
                self.identity["cookie"] = pair
        if exchange.status not in (200, 201):
            return
        path = urlsplit(exchange.url).path or "/"
        if path != "/":
            path = path.rstrip("/")
        try:
            data = json.loads(exchange.body)
        except json.JSONDecodeError:
            return
        if not isinstance(data, dict):
            return
        if path == "/rest/user/login":
            auth = data.get("authentication") if isinstance(data.get("authentication"), dict) else {}
            if auth.get("token"):
                self.identity["token"] = str(auth["token"])
            if auth.get("umail"):
                self.identity["email"] = str(auth["umail"])
            if auth.get("bid") is not None:
                self.identity["basket_id"] = auth["bid"]
            return
        if "login" in path or path.endswith("/session"):
            for key in ("access_token", "id_token", "token"):
                value = data.get(key)
                if isinstance(value, str) and len(value) >= 8:
                    self.identity["token"] = value
                    break
        payload = data.get("user") if isinstance(data.get("user"), dict) else None
        if payload is None and isinstance(data.get("data"), dict):
            payload = data["data"]
        if not isinstance(payload, dict):
            return
        if path == "/rest/user/whoami" or (path == "/api/Users" and exchange.method == "POST"):
            if payload.get("id") is not None:
                self.identity["user_id"] = payload["id"]
            if payload.get("email"):
                self.identity["email"] = str(payload["email"])
