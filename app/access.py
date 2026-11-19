"""Compare two operator sessions. Both logins and every replay go through the charter client."""
from urllib.parse import urlsplit

from .findings import make_finding
from .workers import run_auth_setup, url_for


PRIVILEGED = ("/admin", "/admin/", "/manage", "/staff")
OBJECTS = ("/api/orders/1", "/api/users/1", "/api/Users/1")


def _login(client, account):
    previous_identity = dict(client.identity)
    previous_credentials = dict(client.credentials)
    client.identity.clear()
    client.credentials = {key: account.get(key, "") for key in ("username", "password", "login_url")}
    try:
        run_auth_setup({"intent": "sign in for an access-control comparison", "check": "auth-setup"}, client)
        session = {key: client.identity.get(key, "") for key in ("token", "cookie", "email")}
        session["username"] = account.get("username", "")
        held = getattr(client, "held_secrets", None)
        if held is None:
            client.held_secrets = held = []
        for key in ("token", "cookie"):
            value = session.get(key) or ""
            if isinstance(value, str) and len(value) >= 8 and value not in held:
                held.append(value)
    finally:
        client.identity.clear()
        client.identity.update(previous_identity)
        client.credentials = previous_credentials
    return session


def _activate(client, session):
    client.identity["token"] = session.get("token") or ""
    client.identity["cookie"] = session.get("cookie") or ""


def _targets(client):
    found, seen = [], set()

    def add(url):
        if not url or url in seen:
            return
        seen.add(url)
        found.append(url)

    for path in PRIVILEGED + OBJECTS:
        add(url_for(client, path))
    ledger = getattr(client, "ledger", None)
    if ledger is not None:
        for row in ledger.endpoints.values():
            sample = row.get("sample") or row.get("url") or ""
            path = (row.get("path") or "").lower()
            if any(token in path for token in ("/admin", "/manage", "/order", "/user")):
                add(sample or row.get("url"))
            elif row.get("params") and sample:
                add(sample)
            if len(found) >= 6:
                break
    return found[:6]


def _keep(client, exchange, finding, findings):
    if exchange is None or not finding:
        return
    stored = client.keep(exchange, finding)
    if stored:
        stored["confidence"] = "confirmed"
        findings.append(stored)


def run_access(client, findings):
    """Log in as both operator accounts and replay one role's objects as the other."""
    accounts = [item for item in (getattr(client, "accounts", None) or []) if item.get("username") and item.get("password")]
    if len(accounts) < 2:
        return findings
    high = _login(client, accounts[0])
    low = _login(client, accounts[1])
    if not (high.get("token") or high.get("cookie")) or not (low.get("token") or low.get("cookie")):
        return findings
    high_name = (high.get("username") or "").lower()
    low_name = (low.get("username") or "").lower()
    for url in _targets(client):
        path = urlsplit(url).path or "/"
        _activate(client, high)
        as_high = client.send("GET", url, intent="read an object as the first account", use_session=True)
        _activate(client, low)
        as_low = client.send("GET", url, intent="replay that object as the second account", use_session=True)
        anonymous = None
        if any(part == path.rstrip("/") or path.rstrip("/").endswith(part.rstrip("/")) for part in ("/admin", "/manage", "/staff")):
            client.identity["token"] = ""
            client.identity["cookie"] = ""
            anonymous = client.send("GET", url, intent="request the privileged path with no session", use_session=False)
        low_body = (as_low.body or "") if as_low and not as_low.blocked else ""
        if (as_low and not as_low.blocked and as_low.status == 200 and high_name and high_name in low_body.lower()
                and high_name != low_name):
            finding = make_finding(
                "Low-privilege session reads another account's object", "High",
                f"GET {path} as the second account returned the first account's identity. The body stays in the capture.",
                "Changing the session is enough to read another user's record.",
                "Sign in as each supplied account and request the same object URL.",
                "Authorize the object against the caller and reject every other account.",
                proven=True, check="idor", endpoint=path)
            _keep(client, as_low, finding, findings)
        privileged = any(part.rstrip("/") and path.rstrip("/").endswith(part.rstrip("/")) for part in ("/admin", "/manage", "/staff"))
        anon_denied = anonymous is None or anonymous.blocked or anonymous.status in {401, 403, 404}
        if (privileged and as_low and not as_low.blocked and as_low.status == 200 and anon_denied
                and "admin" in low_body.lower()):
            finding = make_finding(
                "Low-privilege session reaches an admin function", "High",
                f"GET {path} is denied without a session and succeeds for the second account. The body stays in the capture.",
                "A normal account can open a function reserved for an administrator.",
                "Request the path with no session, then again as the second account.",
                "Check the caller's role on the server before returning the admin response.",
                proven=True, check="access", endpoint=path)
            _keep(client, as_low, finding, findings)
    _activate(client, high)
    return findings
