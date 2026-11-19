"""Decide whether a captured exchange proves an issue, and which finding to keep."""
import json
import re
from urllib.parse import urlsplit


_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def make_finding(title, severity, evidence, impact, reproduce, remediation, *, proven, check, endpoint):
    return {"title": title, "severity": severity, "evidence": evidence[:700], "impact": impact,
            "reproduce": reproduce, "remediation": remediation, "proven": bool(proven),
            "check": check, "endpoint": endpoint}


def _rank(finding):
    return _RANK.get(str(finding.get("severity", "")).lower(), 0)


def choose_finding(current, proposed, evidence):
    """Keep a finding only when the run already has HTTP evidence."""
    if not evidence or not isinstance(proposed, dict) or not proposed.get("title"):
        return None
    if current and current.get("proven") and not proposed.get("proven"):
        return current
    if current and current.get("proven") and proposed.get("proven") and _rank(proposed) <= _rank(current):
        return current
    if current and not proposed.get("proven") and _rank(current) > _rank(proposed):
        return current
    return proposed


def _loads(body):
    try:
        return json.loads(body or "")
    except (json.JSONDecodeError, TypeError):
        return None


def _walk(value, visit, depth=0):
    if depth > 8:
        return
    if isinstance(value, dict):
        for key, item in list(value.items())[:40]:
            visit(key, item)
            _walk(item, visit, depth + 1)
    elif isinstance(value, list):
        for item in value[:30]:
            _walk(item, visit, depth + 1)


def _emails(value):
    found = []

    def visit(key, item):
        if str(key).lower() == "email" and isinstance(item, str) and "@" in item:
            found.append(item.strip())

    _walk(value, visit)
    return found


def _ints(value, names):
    found = []

    def visit(key, item):
        if str(key).lower() in names:
            try:
                found.append(int(item))
            except (TypeError, ValueError):
                pass

    _walk(value, visit)
    return found


def _sensitive(value):
    found = []

    def visit(key, item):
        text = str(key).lower().replace("_", "").replace("-", "")
        if item not in (None, "", [], {}) and any(part in text for part in ("password", "secret")):
            found.append(key)

    _walk(value, visit)
    return found


def _path(url):
    path = urlsplit(url).path or "/"
    return path if path == "/" else path.rstrip("/")


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def classify_exchange(exchange, identity):
    """Return a proven access finding, or None. Identity is the lab session, never a token."""
    if exchange.blocked or exchange.skipped or exchange.status != 200 or exchange.method != "GET":
        return None
    path = _path(exchange.url)
    data = _loads(exchange.body)
    if data is None:
        return None
    ours = str(identity.get("email") or "").lower()
    if path == "/api/Users" or re.fullmatch(r"/api/Users/\d+", path):
        others = [email for email in _emails(data) if email.lower() != ours]
        if not others:
            return None
        who = ours or "an unauthenticated request"
        secret = " The records also included a password or secret field." if _sensitive(data) else ""
        shown = ", ".join(others[:3])
        return make_finding(
            "Broken object level authorization on user records",
            "High",
            f"Called as {who}. GET {path} returned account data for {shown}.{secret}",
            "A caller can read account records that belong to other users.",
            "Authenticate as a normal lab user and request /api/Users and /api/Users/{id}. "
            "Compare the returned email addresses with the caller's own account.",
            "Authorize each object against the caller. Return only the caller's own user record.",
            proven=True, check="bola", endpoint=path)
    match = re.fullmatch(r"/rest/basket/(\d+)", path)
    if not match:
        return None
    requested = int(match.group(1))
    our_basket = _as_int(identity.get("basket_id"))
    our_user = _as_int(identity.get("user_id"))
    if our_basket is None or requested == our_basket:
        return None
    if not any(token in exchange.body for token in ("UserId", "userId", "Products", '"id"')):
        return None
    owners = _ints(data, {"userid", "user_id"})
    owner = owners[0] if owners else None
    if owner is not None and our_user is not None and owner == our_user:
        return None
    owner_text = f"user {owner}" if owner is not None else "another basket"
    return make_finding(
        "Broken object level authorization on baskets",
        "High",
        f"The lab session owns basket {our_basket}, but GET /rest/basket/{requested} returned {owner_text}.",
        "Any authenticated customer can read another customer's basket by changing the id.",
        "Log in, note the basket id in the login response, and request a different /rest/basket/{id}.",
        "Bind basket reads to the authenticated user and reject every other id.",
        proven=True, check="bola", endpoint=path)


def misconfig_finding(exchange):
    if exchange.blocked or exchange.skipped or exchange.status != 200:
        return None
    path = _path(exchange.url)
    if path == "/metrics" and any(token in exchange.body for token in ("http_requests", "process_")):
        return make_finding(
            "Application metrics are exposed",
            "Medium",
            "GET /metrics returned process or request metrics without an access check.",
            "Metrics can disclose internal traffic and deployment details.",
            "Request /metrics from the approved origin without credentials.",
            "Require authentication for the metrics endpoint or keep it off the application network.",
            proven=False, check="misconfig", endpoint=path)
    if path == "/ftp" and any(token in exchange.body.lower() for token in ("index of", "href=", "<a ")):
        return make_finding(
            "FTP directory listing is exposed",
            "Medium",
            "GET /ftp returned a directory listing.",
            "Files intended for operators can be downloaded by any client who can reach the origin.",
            "Request /ftp on the approved origin and inspect the listing.",
            "Disable public directory listing and require authorization for those files.",
            proven=False, check="misconfig", endpoint=path)
    if path == "/rest/admin/application-configuration" and exchange.body.lstrip().startswith(("{", "[")):
        if not exchange.authenticated:
            return make_finding(
                "Administration configuration is readable without authentication",
                "Medium",
                "GET /rest/admin/application-configuration returned JSON without a lab session.",
                "Configuration can expose integration settings to every client.",
                "Request the administration configuration route with no session cookie or bearer token.",
                "Require an administrative session before returning configuration.",
                proven=False, check="misconfig", endpoint=path)
    return None


def row_count(body):
    data = _loads(body)
    if isinstance(data, dict) and isinstance(data.get("data"), list):
        return len(data["data"])
    if isinstance(data, list):
        return len(data)
    return None


def sensitive_directory_finding(exchange):
    """An unauthenticated page that renders account secrets is a finding. The values stay in evidence."""
    if exchange.blocked or exchange.skipped or exchange.status != 200 or exchange.authenticated:
        return None
    body = exchange.body or ""
    if not re.search(r"\d{3}-\d{2}-\d{4}", body):
        return None
    lowered = body.lower()
    if "password" not in lowered or "ssn" not in lowered:
        return None
    path = _path(exchange.url)
    return make_finding(
        "Unauthenticated page exposes account secrets",
        "High",
        f"GET {path} returned password and national-identifier fields with no session. "
        "The captured exchange keeps the body. This summary omits the values.",
        "Anyone who can open this URL can read account secrets the application stored in the page.",
        "Request the page on the approved origin with no session cookie or bearer token.",
        "Require an administrative session and stop rendering passwords or national identifiers in the browser.",
        proven=True, check="sensitive-data", endpoint=path)


def disclosure_finding(exchange):
    if exchange.blocked or exchange.skipped:
        return None
    match = re.search(r"Apache Tomcat/[0-9.]+|nginx/[0-9.]+|Microsoft-IIS/[0-9.]+", exchange.body or "")
    if not match:
        return None
    path = _path(exchange.url)
    return make_finding(
        "Server version disclosed in the response body",
        "Low",
        f"{exchange.method} {path} included {match.group(0)} in the response body.",
        "A precise server version makes it easier to match the deployment to a known defect.",
        "Request a missing path on the approved origin and read the error page.",
        "Return a generic error page and keep product version strings off public responses.",
        proven=False, check="disclosure", endpoint=path)


def header_finding(exchange):
    if exchange.blocked or exchange.skipped or exchange.status != 200:
        return None
    headers = {str(key).lower(): str(value) for key, value in (exchange.headers or {}).items()}
    body = exchange.body or ""
    mime = headers.get("content-type", "").split(";")[0].strip().lower()
    html = mime == "text/html" or body.lstrip()[:80].lower().startswith("<!doctype html") or "<html" in body[:400].lower()
    if not html:
        return None
    missing = []
    policy = headers.get("content-security-policy", "")
    if "content-security-policy" not in headers:
        missing.append("Content-Security-Policy")
    if "x-frame-options" not in headers and "frame-ancestors" not in policy.lower():
        missing.append("X-Frame-Options")
    if not missing:
        return None
    path = _path(exchange.url)
    return make_finding(
        "Response is missing browser security headers",
        "Low",
        f"GET {path} returned HTML without {', '.join(missing)}.",
        "The browser is given no response-header policy for script sources or framing. "
        "This observation does not by itself show script execution.",
        "Request the page on the approved origin and inspect the response headers.",
        "Send a Content-Security-Policy and a framing control that match the pages you serve.",
        proven=False, check="headers", endpoint=path)


def role_name(body):
    data = _loads(body)
    found = []

    def visit(key, item):
        if str(key).lower() == "role" and isinstance(item, str):
            found.append(item.lower())

    _walk(data, visit)
    return found[-1] if found else ""
