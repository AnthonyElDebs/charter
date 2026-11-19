"""In-scope checks for the web and API classes the API Top 10 worker does not cover.

Every request goes through the campaign client, which checks the signed charter first.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from urllib.parse import parse_qsl, unquote, urlencode, urljoin, urlsplit

from .findings import make_finding


CHECKS = (
    "xss-reflected", "xss-stored", "sqli", "command-injection", "traversal",
    "ssrf", "open-redirect", "cors", "csrf", "misconfig", "secrets",
    "jwt", "auth-session", "idor", "sweep",
)
SQL_ERRORS = (
    "sql syntax", "sqlite", "mysql", "postgresql", "odbc", "ora-", "unclosed quotation", "sqlstate",
    "microsoft ole db", "incorrect syntax near", "unclosed quotation mark",
    "quoted string not properly terminated", "conversion failed", "sql server", "mssql", "syntax error",
)
CSRF_NAMES = ("csrf", "xsrf", "token", "authenticity", "_token", "csrftoken")
SECRET_PATTERNS = (
    ("cloud access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("embedded credential", re.compile(r"(?i)(?:api[_-]?key|client[_-]?secret|password)\s*[:=]\s*['\"][^'\"]{8,}")),
)
MISCONFIG_PATHS = ("/.env", "/.git/HEAD", "/server-status", "/actuator/env", "/debug", "/phpinfo.php")
WEAK_JWT_SECRETS = ("secret", "password", "changeme")


def _helpers():
    from .workers import observe, url_for
    return observe, url_for


def _origin(url):
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _session(client):
    return bool(client.identity.get("token") or client.identity.get("cookie"))


def _send(client, task, method, url, **kwargs):
    use = kwargs.pop("use_session", None)
    if use is None:
        use = _session(client)
    return client.send(method, url, intent=task["intent"], use_session=bool(use and _session(client)), **kwargs)


def _base(client):
    if client.target:
        return client.target
    rules = client.charter.get("allow") or []
    return rules[0] if rules else ""


def _subject(task, client):
    url = task.get("url") if isinstance(task, dict) else ""
    if isinstance(url, str) and url.startswith(("http://", "https://")):
        return url
    return _base(client)


def _param_names(task, url, defaults):
    supplied = task.get("params") if isinstance(task, dict) else None
    if isinstance(supplied, list):
        names = [name for name in supplied if isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,40}", name)]
        return names[:8]
    parsed = [name for name, _value in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
    if parsed:
        return parsed[:8]
    return list(defaults)


def _sql_sleep():
    try:
        value = float(os.environ.get("CHARTER_SQLI_SLEEP", "2"))
    except (TypeError, ValueError):
        value = 2.0
    return min(5.0, max(0.05, value))


def _norm(body, payload):
    text = (body or "").replace(payload or "", "")
    return re.sub(r"\s+", " ", text).strip()


def _abs(client, path):
    _, url_for = _helpers()
    return url_for(client, path)


def _query(url, params):
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}{parts.path or '/'}?{urlencode(params)}"


def _attr(text, name):
    match = re.search(rf"""\b{name}\s*=\s*["']([^"']*)["']""", text or "", re.I)
    return match.group(1) if match else ""


def _forms(body):
    found = []
    for match in re.finditer(r"<form\b([^>]*)>(.*?)</form>", body or "", re.I | re.S):
        attrs, inner = match.group(1), match.group(2)
        fields = []
        for tag in re.finditer(r"<(?:input|textarea|select)\b([^>]*)>", inner, re.I):
            fields.append({"name": _attr(tag.group(1), "name"),
                           "type": (_attr(tag.group(1), "type") or "text").lower()})
        found.append({"method": (_attr(attrs, "method") or "GET").upper(),
                      "action": _attr(attrs, "action"), "fields": fields})
        if len(found) >= 4:
            break
    return found


def _scripts(body):
    return re.findall(r"""<script\b[^>]*\bsrc=["']([^"']+)["']""", body or "", re.I)[:4]


def _same_origin(page, link):
    left, right = urlsplit(page), urlsplit(link)
    if left.scheme not in {"http", "https"} or right.scheme not in {"http", "https"}:
        return False
    return (left.hostname or "").lower() == (right.hostname or "").lower()


def _keep(client, exchange, finding, findings, lines):
    observe, _url_for = _helpers()
    found, text = observe(client, exchange)
    findings.extend(found)
    if text:
        lines.append(text)
    if finding and exchange is not None and not exchange.blocked and not exchange.skipped:
        stored = client.keep(exchange, finding)
        if stored:
            findings.append(stored)
            lines.append(f"finding: {stored['title']} proven={'true' if stored.get('proven') else 'false'} run={stored['run_id']}")
    return findings, lines


def _result(lines, findings, fallback):
    from .workers import StepResult
    return StepResult("\n".join(line for line in lines if line) or fallback, findings)


def _emails(body):
    try:
        data = json.loads(body or "")
    except (json.JSONDecodeError, TypeError):
        return []
    found = []

    def walk(value):
        if isinstance(value, dict):
            for key, item in list(value.items())[:30]:
                if str(key).lower() == "email" and isinstance(item, str) and "@" in item:
                    found.append(item.lower())
                else:
                    walk(item)
        elif isinstance(value, list):
            for item in value[:20]:
                walk(item)

    walk(data)
    return found


def _reflected(body, marker):
    """True when the probe tag is present as markup. An HTML-escaped copy does not count."""
    return f"<{marker}>" in (body or "")


def run_xss_reflected(task, client):
    token = secrets.token_hex(3)
    marker = f"charterxss{token}"
    payload = f'"><{marker}>'
    base = _subject(task, client)
    if not base:
        return _result([], [], "no in-scope URL for reflected XSS")
    names = _param_names(task, base, ["q"])
    findings, lines = [], []
    for name in names:
        exchange = _send(client, task, "GET", _query(base, {name: payload}))
        finding = None
        if exchange and not exchange.blocked and not exchange.skipped and _reflected(exchange.body, marker):
            path = urlsplit(exchange.url).path or "/"
            finding = make_finding(
                "Reflected input is returned without encoding", "High",
                f"GET {path} parameter {name} echoed the probe tag without HTML encoding.",
                "A browser that opens this URL can treat the reflected characters as markup.",
                "Repeat the request on the approved origin with the same probe in the parameter.",
                "Encode the parameter for the HTML context before writing it into the page.",
                proven=True, check="xss-reflected", endpoint=path)
        _keep(client, exchange, finding, findings, lines)
        if finding:
            break
    return _result(lines, findings, "no reflected markup")


def run_xss_stored(task, client):
    token = secrets.token_hex(3)
    marker = f'"><charterxss{token}>'
    base = _subject(task, client)
    if not base:
        return _result([], [], "no in-scope page for stored XSS")
    supplied = task.get("forms") if isinstance(task.get("forms"), list) and task.get("forms") else None
    findings, lines = [], []
    if supplied:
        forms = supplied
        page_url = base
    else:
        page = _send(client, task, "GET", base.split("?")[0], use_session=False)
        _keep(client, page, None, findings, lines)
        forms = _forms(page.body if page else "")
        page_url = page.url if page else base
    for form in forms:
        if form["method"] != "POST":
            continue
        action = urljoin(page_url, form.get("action") or page_url)
        if not _same_origin(page_url, action):
            continue
        body = {field["name"]: marker for field in form["fields"] if field["name"]} or {"comment": marker}
        posted = _send(client, task, "POST", action, body=body)
        _keep(client, posted, None, findings, lines)
        again = _send(client, task, "GET", action.split("?")[0])
        finding = None
        if again and not again.blocked and marker in (again.body or "") and marker not in again.url:
            path = urlsplit(again.url).path or "/"
            finding = make_finding(
                "Stored input is rendered without encoding", "High",
                f"A later GET {path} rendered the probe that was posted earlier, without HTML encoding.",
                "Anyone who opens the page can receive markup that another caller stored.",
                "Submit the probe on the approved origin, then request the page again with a clean URL.",
                "Encode stored text for the HTML context on output, and reject unexpected markup on input.",
                proven=True, check="xss-stored", endpoint=path)
        _keep(client, again, finding, findings, lines)
        break
    return _result(lines, findings, "no stored markup")


def _sqli_finding(exchange, name, title, detail):
    path = urlsplit(exchange.url).path or "/"
    return make_finding(
        title, "High",
        f"GET {path} parameter {name}: {detail}",
        "The parameter is being combined with a SQL statement.",
        "Repeat the baseline and the probe on the approved origin and compare the responses.",
        "Bind the value as a parameter. Do not concatenate it into the statement.",
        proven=True, check="sqli", endpoint=path)


def _error_sqli(task, client, base, name, findings, lines):
    baseline = _send(client, task, "GET", _query(base, {name: "charterbase"}))
    injected = _send(client, task, "GET", _query(base, {name: "charterbase'"}))
    finding = None
    if injected and baseline and not injected.blocked and not baseline.blocked:
        low = (injected.body or "").lower()
        base_low = (baseline.body or "").lower()
        if any(word in low and word not in base_low for word in SQL_ERRORS):
            finding = _sqli_finding(injected, name, "SQL error after a quote in a parameter",
                                    "a database error appeared after a single quote and was absent from the baseline.")
    for exchange in (baseline, injected):
        _keep(client, exchange, finding if exchange is injected else None, findings, lines)
    return finding


def _boolean_sqli(task, client, base, name, findings, lines):
    pairs = (("1", "1 AND 1=1", "1 AND 1=2"), ("charter", "charter' OR '1'='1", "charter' OR '1'='2"))
    for plain, truth, falsehood in pairs:
        baseline = _send(client, task, "GET", _query(base, {name: plain}))
        truth_ex = _send(client, task, "GET", _query(base, {name: truth}))
        false_ex = _send(client, task, "GET", _query(base, {name: falsehood}))
        finding = None
        if all(item and not item.blocked and not item.skipped for item in (baseline, truth_ex, false_ex)):
            base_n = _norm(baseline.body, plain)
            true_n = _norm(truth_ex.body, truth)
            false_n = _norm(false_ex.body, falsehood)
            if (true_n != false_n and abs(len(true_n) - len(false_n)) >= 40
                    and abs(len(true_n) - len(base_n)) + 20 < abs(len(false_n) - len(base_n))):
                finding = _sqli_finding(
                    truth_ex, name, "Boolean SQL condition changes the response",
                    "a true condition tracked the baseline and the false condition did not.")
        for exchange in (baseline, truth_ex, false_ex):
            _keep(client, exchange, finding if exchange is truth_ex else None, findings, lines)
        if finding:
            return finding
    return None


def _timed(task, client, base, name, payload):
    started = time.monotonic()
    exchange = _send(client, task, "GET", _query(base, {name: payload}))
    return exchange, time.monotonic() - started


def _time_sqli(task, client, base, name, findings, lines):
    delay = _sql_sleep()
    baseline, base_elapsed = _timed(task, client, base, name, "1")
    payloads = ("1;WAITFOR DELAY '0:0:2'--", "1' AND SLEEP(2)--")
    finding = None
    delayed = None
    for payload in payloads:
        delayed, elapsed = _timed(task, client, base, name, payload)
        if (delayed and baseline and not delayed.blocked and not baseline.blocked
                and elapsed - base_elapsed >= delay * 0.75 and elapsed >= delay * 0.75):
            finding = _sqli_finding(delayed, name, "Delayed SQL statement changes the response time",
                                    "the probe took longer than the baseline by the configured SQL delay.")
            break
    for exchange in (baseline, delayed):
        _keep(client, exchange, finding if exchange is delayed else None, findings, lines)
    return finding


def _wants_time(name):
    low = re.sub(r"[^a-z0-9]", "", str(name).lower())
    return low in {"id", "item", "num", "cat", "pid", "uid", "product", "productid"} or low.endswith("id")


def run_sqli(task, client):
    base = _subject(task, client)
    if not base:
        return _result([], [], "no in-scope URL for SQL injection")
    names = _param_names(task, base, ["q", "id", "search"])
    findings, lines = [], []
    for name in names:
        if _error_sqli(task, client, base, name, findings, lines):
            return _result(lines, findings, "no SQL error difference")
        if _boolean_sqli(task, client, base, name, findings, lines):
            return _result(lines, findings, "no SQL error difference")
        if _wants_time(name) and _time_sqli(task, client, base, name, findings, lines):
            return _result(lines, findings, "no SQL error difference")
    return _result(lines, findings, "no SQL error difference")


def run_command_injection(task, client):
    token = secrets.token_hex(3)
    expected = f"chartercmd{token}"
    payload = f"$(printf charter%s cmd{token})"
    base = _base(client)
    if not base:
        return _result([], [], "no in-scope URL for command injection")
    url = _query(base, {"q": payload})
    exchange = _send(client, task, "GET", url)
    finding = None
    if (exchange and not exchange.blocked and not exchange.skipped and expected in (exchange.body or "")
            and expected not in payload):
        path = urlsplit(exchange.url).path or "/"
        finding = make_finding(
            "Parameter value was executed as a command", "Critical",
            f"GET {path} returned command output that was not present in the request value.",
            "The server passed the parameter to a command shell.",
            "Repeat the request on the approved origin and compare the output with a plain value.",
            "Do not pass request data to a shell. Call the program with an argument array.",
            proven=True, check="command-injection", endpoint=path)
    findings, lines = [], []
    _keep(client, exchange, finding, findings, lines)
    return _result(lines, findings, "no command execution")


TRAVERSAL_PROBES = (
    ("../../../../etc/passwd", ("root:x:0:0:",)),
    ("..\\..\\..\\boot.ini", ("[boot loader]",)),
    ("..%2f..%2f..%2fetc/passwd", ("root:x:0:0:",)),
)


def run_traversal(task, client):
    base = _subject(task, client)
    if not base:
        return _result([], [], "no in-scope URL for path traversal")
    names = _param_names(task, base, ["file"])[:4]
    findings, lines = [], []
    for name in names:
        for payload, signatures in TRAVERSAL_PROBES:
            exchange = _send(client, task, "GET", _query(base, {name: payload}))
            body = exchange.body or "" if exchange else ""
            finding = None
            if exchange and not exchange.blocked and any(sig in body for sig in signatures):
                path = urlsplit(exchange.url).path or "/"
                finding = make_finding(
                    "Parameter reads a file outside the application directory", "High",
                    f"GET {path} parameter {name} returned a file signature from outside the application directory. "
                    "The file contents are only in the captured body.",
                    "The file parameter can be walked out of the intended directory.",
                    "Request the approved URL with a parent-directory file value and compare it with a normal file name.",
                    "Map the parameter to a known file id, or confine it to a canonical directory.",
                    proven=True, check="traversal", endpoint=path)
            _keep(client, exchange, finding, findings, lines)
            if finding:
                return _result(lines, findings, "no traversed file")
    return _result(lines, findings, "no traversed file")


def run_ssrf(task, client):
    base = _subject(task, client)
    if not base:
        return _result([], [], "no in-scope URL for SSRF")
    name = (_param_names(task, base, ["url"]) or ["url"])[0]
    origin = _origin(base)
    baseline = _send(client, task, "GET", _query(base, {name: "charter"}))
    fetched = _send(client, task, "GET", _query(base, {name: origin + "/robots.txt"}))
    finding = None
    if fetched and baseline and not fetched.blocked and not baseline.blocked:
        if "User-agent" in (fetched.body or "") and "User-agent" not in (baseline.body or ""):
            path = urlsplit(fetched.url).path or "/"
            finding = make_finding(
                "The server requested a URL taken from a parameter", "High",
                f"GET {path} included the robots file after the parameter named an in-scope URL. "
                "The baseline response did not.",
                "An attacker can choose a URL the server will request.",
                "Compare a normal parameter with one set to another path on the approved origin.",
                "Allow only a fixed set of destinations, and do not request URLs supplied by the caller.",
                proven=True, check="ssrf", endpoint=path)
    findings, lines = [], []
    for exchange in (baseline, fetched):
        _keep(client, exchange, finding if exchange is fetched else None, findings, lines)
    return _result(lines, findings, "no server-side request")


REDIRECT_PROBES = ("https://example.invalid/charter", "https:%2F%2Fexample.invalid/charter")
_REDIRECT_SINKS = (
    re.compile(r"""http-equiv\s*=\s*["']?refresh["']?[^>]*\burl\s*=\s*['"]?([^'">\s]+)""", re.I),
    re.compile(r"""(?:window\.|document\.|self\.)?location(?:\.href|\.assign)?\s*=\s*['"]([^'"]+)['"]""", re.I),
    re.compile(r"""location\.replace\(\s*['"]([^'"]+)['"]\s*\)""", re.I),
)


def _offsite(value):
    text = unquote(value or "")
    if "example.invalid" not in text.lower():
        return False
    host = (urlsplit(text).hostname or "")
    if not host and text.startswith("//"):
        host = urlsplit("http:" + text).hostname or ""
    return host.lower() == "example.invalid"


def _redirected(exchange):
    if exchange is None or exchange.blocked:
        return False
    if _offsite(exchange.headers.get("location", "")):
        return True
    body = unquote(exchange.body or "")
    return any(_offsite(match.group(1)) for pattern in _REDIRECT_SINKS for match in pattern.finditer(body))


def run_open_redirect(task, client):
    base = _subject(task, client)
    if not base:
        return _result([], [], "no in-scope URL for open redirect")
    names = _param_names(task, base, ["next"])[:4]
    findings, lines = [], []
    for name in names:
        for payload in REDIRECT_PROBES:
            exchange = _send(client, task, "GET", _query(base, {name: payload}))
            finding = None
            if _redirected(exchange):
                path = urlsplit(exchange.url).path or "/"
                finding = make_finding(
                    "Redirect target is taken from the request", "Medium",
                    f"GET {path} sent the browser to a host supplied in the {name} parameter. The redirect was not followed.",
                    "A caller can send someone from the approved site to an arbitrary host.",
                    "Request the approved URL with an external redirect value and read Location or the page redirect. Do not follow it.",
                    "Accept only relative paths, or compare the target with an allow list of your own hosts.",
                    proven=True, check="open-redirect", endpoint=path)
            _keep(client, exchange, finding, findings, lines)
            if finding:
                return _result(lines, findings, "no open redirect")
    return _result(lines, findings, "no open redirect")


def run_cors(task, client):
    base = _base(client)
    if not base:
        return _result([], [], "no in-scope URL for CORS")
    exchange = _send(client, task, "GET", base.split("?")[0], headers={"origin": "https://charter.invalid"})
    finding = None
    if exchange and not exchange.blocked:
        allow = exchange.headers.get("access-control-allow-origin", "")
        credentials = exchange.headers.get("access-control-allow-credentials", "")
        if allow == "*" or allow == "https://charter.invalid":
            path = urlsplit(exchange.url).path or "/"
            finding = make_finding(
                "Cross-origin responses trust an arbitrary origin", "Medium",
                f"GET {path} returned Access-Control-Allow-Origin: {allow}.",
                "A page on another host can read the response with the caller's cookies if credentials are allowed."
                if credentials.lower() == "true" else
                "A page on another host is allowed to read this response.",
                "Repeat the request on the approved origin with an Origin header you do not own.",
                "Reflect only origins you operate, and do not combine a wildcard with credentials.",
                proven=True, check="cors", endpoint=path)
    findings, lines = [], []
    _keep(client, exchange, finding, findings, lines)
    return _result(lines, findings, "no insecure CORS header")


def run_csrf(task, client):
    base = _subject(task, client)
    if not base:
        return _result([], [], "no in-scope page for CSRF")
    supplied = task.get("forms") if isinstance(task.get("forms"), list) and task.get("forms") else None
    findings, lines = [], []
    if supplied:
        forms = supplied
        page_url = base
    else:
        page = _send(client, task, "GET", base.split("?")[0])
        _keep(client, page, None, findings, lines)
        forms = _forms(page.body if page else "")
        page_url = page.url if page else base
    for form in forms:
        if form["method"] not in {"POST", "PUT", "PATCH", "DELETE"}:
            continue
        names = " ".join(field["name"] or "" for field in form["fields"]).lower()
        if any(token in names for token in CSRF_NAMES):
            continue
        action = urljoin(page_url, form.get("action") or page_url)
        if not _same_origin(page_url, action):
            continue
        posted = _send(client, task, "POST", action, body={"charter": "1"})
        path = urlsplit(action).path or "/"
        proven = posted is not None and not posted.blocked and posted.status < 400
        finding = make_finding(
            "State-changing form has no anti-CSRF token", "Medium" if proven else "Low",
            f"POST {path} has no CSRF field. The trial request returned {getattr(posted, 'status', 0)}.",
            "Another site can submit the form while the browser is logged in.",
            "Read the form on the approved origin and submit it without a token.",
            "Require a per-session token on every state-changing request and check it on the server.",
            proven=proven, check="csrf", endpoint=path)
        _keep(client, posted, finding, findings, lines)
        break
    return _result(lines, findings, "no tokenless state-changing form")


def run_misconfig(task, client):
    findings, lines = [], []
    home = _abs(client, "/")
    if home:
        _keep(client, _send(client, task, "GET", home, use_session=False), None, findings, lines)
    for path in MISCONFIG_PATHS:
        url = _abs(client, path)
        if not url:
            continue
        exchange = _send(client, task, "GET", url, use_session=False)
        body = exchange.body or "" if exchange else ""
        finding = None
        if exchange and not exchange.blocked and exchange.status == 200:
            title = evidence = remediation = ""
            if path == "/.env" and re.search(r"(?i)(password|secret|api_key)\s*=", body):
                title, evidence = "Environment file is readable", "GET /.env returned credential assignments. Values stay in the capture."
                remediation = "Remove the file from the web root and keep secrets in the process environment."
            elif path == "/.git/HEAD" and "ref: refs/" in body:
                title, evidence = "Git metadata is readable", "GET /.git/HEAD returned a Git ref."
                remediation = "Do not publish the .git directory."
            elif path == "/phpinfo.php" and "php version" in body.lower():
                title, evidence = "PHP information page is exposed", "GET /phpinfo.php returned a PHP information page."
                remediation = "Remove phpinfo from the deployed application."
            elif path in {"/server-status", "/actuator/env", "/debug"} and exchange.status == 200 and body.strip().startswith(("{", "[")):
                title, evidence = "Debug or status endpoint is exposed", f"GET {path} returned structured status data."
                remediation = "Require an administrative session or remove the endpoint from the public application."
            if title:
                finding = make_finding(
                    title, "Medium", evidence,
                    "The response discloses deployment or credential material to anyone who can reach the origin.",
                    f"Request {path} on the approved origin without a session.",
                    remediation, proven=True, check="misconfig", endpoint=path)
        _keep(client, exchange, finding, findings, lines)
    return _result(lines, findings, "no exposed configuration")


def run_secrets(task, client):
    base = _base(client)
    if not base:
        return _result([], [], "no in-scope page for secret scanning")
    page = _send(client, task, "GET", base.split("?")[0], use_session=False)
    findings, lines = [], []
    _keep(client, page, None, findings, lines)
    for src in _scripts(page.body if page else ""):
        absolute = urljoin(page.url, src)
        if not _same_origin(page.url, absolute):
            continue
        exchange = _send(client, task, "GET", absolute.split("?")[0], use_session=False)
        finding = None
        text = exchange.body or "" if exchange else ""
        for label, pattern in SECRET_PATTERNS:
            if exchange and not exchange.blocked and pattern.search(text):
                path = urlsplit(exchange.url).path or "/"
                finding = make_finding(
                    "Script contains a credential pattern", "High",
                    f"GET {path} matched a {label}. The value is only in the captured body.",
                    "Anyone who can download the script can reuse the credential.",
                    "Download the script from the approved origin and search for the pattern. Do not copy the value into notes.",
                    "Remove the credential from client-side code and rotate it.",
                    proven=True, check="secrets", endpoint=path)
                break
        _keep(client, exchange, finding, findings, lines)
    return _result(lines, findings, "no credential pattern in scripts")


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_json(text):
    pad = "=" * (-len(text) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(text + pad))
    except (json.JSONDecodeError, ValueError, TypeError):
        return None


def _jwt_none(payload):
    return _b64url(b'{"alg":"none","typ":"JWT"}') + "." + _b64url(json.dumps(payload).encode()) + "."


def _jwt_hs(payload, secret):
    header = _b64url(b'{"alg":"HS256","typ":"JWT"}')
    body = _b64url(json.dumps(payload).encode())
    signature = hmac.new(secret.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{_b64url(signature)}"


def run_jwt(task, client):
    token = str(client.identity.get("token") or "")
    if token.count(".") != 2:
        base = _base(client)
        page = _send(client, task, "GET", base.split("?")[0]) if base else None
        match = re.search(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*", (page.body if page else "") or "")
        token = match.group(0) if match else ""
    payload = _b64url_json(token.split(".")[1]) if token.count(".") >= 1 else None
    if not isinstance(payload, dict):
        return _result([], [], "no JWT observed")
    protected = _abs(client, "/api/profile") or _abs(client, "/rest/user/whoami") or _abs(client, "/api/Users")
    if not protected:
        return _result([], [], "no in-scope profile URL for the JWT check")
    anonymous = _send(client, task, "GET", protected, use_session=False)
    findings, lines = [], []
    _keep(client, anonymous, None, findings, lines)
    if anonymous is None or anonymous.blocked or anonymous.status not in {401, 403}:
        return _result(lines, findings, "profile URL did not require a token")
    candidates = [("alg none", _jwt_none(payload))]
    candidates.extend((f"HMAC secret {name}", _jwt_hs(payload, name)) for name in WEAK_JWT_SECRETS)
    for label, forged in candidates:
        exchange = _send(client, task, "GET", protected, headers={"authorization": "Bearer " + forged}, use_session=False)
        finding = None
        if exchange and not exchange.blocked and exchange.status == 200:
            finding = make_finding(
                "API accepted a forged JSON Web Token", "Critical",
                f"GET {urlsplit(protected).path} rejected an anonymous request and accepted a token signed as {label}. "
                "The token is not repeated here.",
                "A caller can mint a token the API will trust.",
                "Request the approved profile URL with no token, then with the forged token described in the evidence record.",
                "Reject alg none, and verify HMAC tokens with a long random secret that is not a dictionary word.",
                proven=True, check="jwt", endpoint=urlsplit(protected).path or "/")
        _keep(client, exchange, finding, findings, lines)
        if finding:
            break
    return _result(lines, findings, "forged tokens were rejected")


def run_auth_session(task, client):
    base = _base(client)
    if not base:
        return _result([], [], "no in-scope URL for session checks")
    exchange = _send(client, task, "GET", base.split("?")[0], use_session=False)
    findings, lines = [], []
    cookie = exchange.headers.get("set-cookie", "") if exchange else ""
    finding = None
    if exchange and not exchange.blocked and cookie:
        lowered = cookie.lower()
        session_name = any(name in lowered for name in ("session", "sid", "jwt", "auth"))
        if session_name and ("httponly" not in lowered or "samesite" not in lowered):
            path = urlsplit(exchange.url).path or "/"
            missing = []
            if "httponly" not in lowered:
                missing.append("HttpOnly")
            if "samesite" not in lowered:
                missing.append("SameSite")
            finding = make_finding(
                "Session cookie is missing browser protections", "Medium",
                f"GET {path} set a session cookie without {', '.join(missing)}. The cookie value is not repeated.",
                "A script or another site has a wider opportunity to reuse the session.",
                "Request the approved page and inspect Set-Cookie. Do not copy the value.",
                "Set HttpOnly and SameSite on the session cookie, and Secure when the site is HTTPS.",
                proven=True, check="auth-session", endpoint=path)
    _keep(client, exchange, finding, findings, lines)
    page = exchange.body or "" if exchange else ""
    if exchange and not exchange.blocked and re.search(r"type=[\"']password", page, re.I) and urlsplit(exchange.url).scheme == "http":
        host = (urlsplit(exchange.url).hostname or "").lower()
        if host not in {"localhost", "127.0.0.1", "juice-shop"}:
            path = urlsplit(exchange.url).path or "/"
            extra = make_finding(
                "Password form is served over cleartext HTTP", "Medium",
                f"GET {path} includes a password field and the URL scheme is http.",
                "The password can be read on the network path to the server.",
                "Open the approved login page and confirm the scheme.",
                "Serve the login page only over HTTPS.",
                proven=True, check="auth-session", endpoint=path)
            stored = client.keep(exchange, extra)
            if stored:
                findings.append(stored)
    return _result(lines, findings, "no session-cookie weakness")


def run_idor(task, client):
    findings, lines = [], []
    seen = {}
    compared = None
    for path in ("/api/items/1", "/api/items/2", "/api/Users/1", "/api/Users/2"):
        url = _abs(client, path)
        if not url:
            continue
        anonymous = _send(client, task, "GET", url, use_session=False)
        authenticated = _send(client, task, "GET", url) if _session(client) else None
        for exchange in (anonymous, authenticated):
            if exchange is None:
                continue
            emails = [] if exchange.blocked else _emails(exchange.body)
            seen.setdefault(path, []).extend(emails)
            finding = None
            if exchange is anonymous and emails and not exchange.blocked and exchange.status == 200:
                finding = make_finding(
                    "Object record is readable without authentication", "High",
                    f"GET {path} returned an account email with no session. The address stays in the capture.",
                    "Anyone who can reach the origin can read the object.",
                    "Request the approved object URL with no cookie or bearer token.",
                    "Require a session and return the object only when it belongs to the caller.",
                    proven=True, check="idor", endpoint=path)
            if exchange is authenticated and emails and not exchange.blocked:
                compared = exchange
            _keep(client, exchange, finding, findings, lines)
    first = seen.get("/api/items/1") or seen.get("/api/Users/1") or []
    second = seen.get("/api/items/2") or seen.get("/api/Users/2") or []
    if first and second and set(first) != set(second) and compared is not None:
        path = urlsplit(compared.url).path or "/"
        stored = client.keep(compared, make_finding(
            "Authenticated request reads another object's record", "High",
            f"The same session received different account emails for two object ids. GET {path} is one of them. "
            "The addresses stay in the captures.",
            "Changing the object id returns a record that belongs to someone else.",
            "Authenticate on the approved origin and request two neighboring object ids.",
            "Authorize each object against the caller and reject every other id.",
            proven=True, check="idor", endpoint=path))
        if stored:
            findings.append(stored)
            lines.append(f"finding: {stored['title']} proven=true run={stored['run_id']}")
    return _result(lines, findings, "no cross-object read")


def execute_coverage(task, client):
    check = task.get("check")
    runners = {
        "xss-reflected": run_xss_reflected,
        "xss-stored": run_xss_stored,
        "sqli": run_sqli,
        "command-injection": run_command_injection,
        "traversal": run_traversal,
        "ssrf": run_ssrf,
        "open-redirect": run_open_redirect,
        "cors": run_cors,
        "csrf": run_csrf,
        "misconfig": run_misconfig,
        "secrets": run_secrets,
        "jwt": run_jwt,
        "auth-session": run_auth_session,
        "idor": run_idor,
    }
    if check == "sweep":
        from .workers import StepResult
        ledger = getattr(client, "ledger", None)
        if ledger is not None and ledger.endpoints:
            from .pipeline import run_pipeline
            return run_pipeline(client)
        findings, lines = [], []
        for name in runners:
            result = runners[name](task, client)
            findings.extend(result.findings)
            if result.observation:
                lines.append(result.observation)
        return StepResult("\n".join(lines) or "coverage sweep finished", findings)
    runner = runners.get(check)
    if runner is None:
        from .workers import StepResult
        return StepResult("unknown coverage check", [])
    return runner(task, client)
