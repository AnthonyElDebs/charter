"""Workers for one campaign step. Every URL is checked by the client before it is sent."""
from pathlib import Path
import re
import secrets
import shutil
import subprocess
from tempfile import TemporaryDirectory
from urllib.parse import urlencode, urljoin, urlsplit

from charter import Refused
from .exchange import describe
from .findings import (classify_exchange, disclosure_finding, header_finding, make_finding,
                       misconfig_finding, role_name, row_count, sensitive_directory_finding)
from .scope_gate import fatal_scope


PATHS = ("/", "/robots.txt", "/api-docs", "/rest/products", "/ftp", "/metrics",
         "/encryptionkeys", "/api/SecurityQuestions", "/rest/admin/application-configuration")
GENERIC_PATHS = ("/login.html", "/feedback.html", "/online-banking.html", "/faq.html", "/help.html",
                 "/search.html", "/admin/", "/admin/index.html", "/admin/users.html", "/admin/currencies.html")
API_PATHS = ("/api-docs", "/rest/products", "/api/SecurityQuestions", "/metrics", "/ftp",
             "/rest/admin/application-configuration")
DEFAULT_WORDS = ("api", "rest", "ftp", "metrics", "admin", "robots.txt", "encryptionkeys", "api-docs")
SQLI_PAYLOAD = "'))OR(1=1)--"
SQLI_BASELINE = "charterzzznomatch"


class StepResult:
    def __init__(self, observation, findings=None):
        self.observation = observation
        self.findings = findings or []


def under_rule(rule, path):
    parts = urlsplit(rule)
    prefix = parts.path or "/"
    if prefix != "/":
        prefix = prefix.rstrip("/")
    if prefix != "/" and path != prefix and not path.startswith(prefix + "/"):
        return None
    return f"{parts.scheme}://{parts.netloc}{path}"


def url_for(client, path):
    if client.target:
        parts = urlsplit(client.target)
        if parts.scheme and parts.netloc:
            return f"{parts.scheme}://{parts.netloc}{path}"
    rules = client.charter.get("allow") or []
    if not rules:
        return None
    return under_rule(rules[0], path)


def candidates(client, paths):
    urls, seen = [], set()
    if client.target:
        seen.add(client.target)
        urls.append(client.target)
    for rule in client.charter.get("allow") or []:
        for path in paths:
            url = under_rule(rule, path)
            if url and url not in seen:
                seen.add(url)
                urls.append(url)
    return urls[:24]


def observe(client, exchange):
    if exchange is None:
        return [], ""
    if exchange.blocked or exchange.skipped:
        return [], describe(exchange)
    candidate = (classify_exchange(exchange, client.identity) or sensitive_directory_finding(exchange)
                 or misconfig_finding(exchange) or disclosure_finding(exchange) or header_finding(exchange))
    stored = client.keep(exchange, candidate) if candidate else None
    findings = [stored] if stored else []
    text = describe(exchange)
    if stored:
        text += f"\nfinding: {stored['title']} proven={'true' if stored.get('proven') else 'false'} run={stored['run_id']}"
    elif candidate:
        text += "\nfinding not stored: the exchange has no committed evidence"
    return findings, text


def _guard(client, url, intent):
    try:
        client.enforce(url)
    except Refused as exc:
        client.store.note_block(client.campaign_id, url, str(exc), intent)
        if fatal_scope(str(exc)):
            raise
        return StepResult(f"refused before send: {exc}", [])
    return None


def _same_origin(page, link):
    left, right = urlsplit(page), urlsplit(link)
    if left.scheme not in {"http", "https"} or right.scheme not in {"http", "https"}:
        return False
    if (left.hostname or "").lower() != (right.hostname or "").lower():
        return False
    def port(parts):
        return parts.port or (443 if parts.scheme == "https" else 80)
    return port(left) == port(right)


def page_links(page_url, body):
    """Same-origin links and form actions from one response. Other hosts are ignored."""
    found, seen = [], set()
    for raw in re.findall(r"""(?:href|action)\s*=\s*["']([^"'#]+)""", str(body)[:100000], re.I):
        raw = raw.strip()
        if raw.lower().startswith(("javascript:", "mailto:", "data:")):
            continue
        absolute = urljoin(page_url, raw)
        parts = urlsplit(absolute)
        path = parts.path or "/"
        if re.search(r"\.(?:css|js|png|jpe?g|gif|svg|ico|woff2?|map)$", path, re.I):
            continue
        if not _same_origin(page_url, absolute):
            continue
        if parts.query and not re.fullmatch(r"[A-Za-z0-9._~%=&+-]*", parts.query):
            continue
        url = f"{parts.scheme}://{parts.netloc}{path}"
        if parts.query:
            url += "?" + parts.query
        if url in seen:
            continue
        seen.add(url)
        found.append(url)
        if len(found) >= 8:
            break
    return found


def discover(task, client, paths):
    if client.charter.get("allow"):
        client.enforce(client.target or client.charter["allow"][0])
    findings, lines, pages = [], [], []
    for url in candidates(client, paths):
        exchange = client.send("GET", url, intent=task["intent"])
        pages.append(exchange)
        found, text = observe(client, exchange)
        findings.extend(found)
        if not (exchange.blocked and "allow rule" in exchange.reason):
            lines.append(text)
    seen = {urlsplit(exchange.url)._replace(query="", fragment="").geturl() for exchange in pages}
    extra = []
    for exchange in pages:
        if exchange.blocked or exchange.skipped:
            continue
        for link in page_links(exchange.url, exchange.body):
            key = urlsplit(link)._replace(query="", fragment="").geturl()
            if key in seen:
                continue
            seen.add(key)
            extra.append(link)
            if len(extra) >= 8:
                break
        if len(extra) >= 8:
            break
    for url in extra:
        exchange = client.send("GET", url, intent=task["intent"])
        found, text = observe(client, exchange)
        findings.extend(found)
        if text:
            lines.append(text)
    return StepResult("\n".join(lines) or "no in-scope discovery URL", findings)


def run_recon(task, client):
    return discover(task, client, PATHS + GENERIC_PATHS)


def run_http(task, client):
    exchange = client.send(task.get("method", "GET"), task["url"], headers=task.get("headers"),
                           body=task.get("body"), intent=task["intent"], use_session=bool(task.get("use_session")))
    found, text = observe(client, exchange)
    return StepResult(text, found)


def _question_id(body):
    try:
        import json
        data = json.loads(body or "")
    except (json.JSONDecodeError, TypeError):
        return 1
    rows = data.get("data") if isinstance(data, dict) and "data" in data else data
    if isinstance(rows, list) and rows and isinstance(rows[0], dict):
        return rows[0].get("id", 1) or 1
    return 1


def run_auth_setup(task, client):
    questions_url = url_for(client, "/api/SecurityQuestions")
    register_url = url_for(client, "/api/Users")
    login_url = url_for(client, "/rest/user/login")
    who_url = url_for(client, "/rest/user/whoami")
    questions = client.send("GET", questions_url, intent=task["intent"]) if questions_url else None
    email = f"charter-{secrets.token_hex(4)}@juice-sh.op"
    password = "Lab-" + secrets.token_hex(8)
    body = {"email": email, "password": password, "passwordRepeat": password,
            "securityQuestion": {"id": _question_id(questions.body if questions else "")},
            "securityAnswer": secrets.token_hex(4)}
    created = client.send("POST", register_url, body=body, intent=task["intent"]) if register_url else None
    logged = client.send("POST", login_url, body={"email": email, "password": password},
                         intent=task["intent"]) if login_url else None
    who = client.send("GET", who_url, use_session=True, intent=task["intent"]) if who_url and client.identity.get("token") else None
    findings, lines = [], []
    for exchange in (questions, created, logged, who):
        found, text = observe(client, exchange)
        findings.extend(found)
        if text:
            lines.append(text)
    if client.identity.get("token"):
        header = (f"Authenticated. email={client.identity.get('email', '')} "
                  f"user_id={client.identity.get('user_id')} basket_id={client.identity.get('basket_id')}. "
                  "Session retained by the worker.")
        return StepResult(header + "\n" + "\n".join(lines), findings)
    return StepResult("Authentication failed.\n" + "\n".join(lines), findings)


def run_bola(task, client):
    if not client.identity.get("token"):
        return StepResult("no lab session; run auth-setup first", [])
    findings, lines = [], []
    for path in ("/api/Users", "/api/Users/1"):
        url = url_for(client, path)
        if not url:
            continue
        found, text = observe(client, client.send("GET", url, use_session=True, intent=task["intent"]))
        findings.extend(found)
        lines.append(text)
    basket = client.identity.get("basket_id")
    try:
        other = 2 if int(basket) == 1 else 1
    except (TypeError, ValueError):
        other = 1
    url = url_for(client, f"/rest/basket/{other}")
    if url:
        found, text = observe(client, client.send("GET", url, use_session=True, intent=task["intent"]))
        findings.extend(found)
        lines.append(text)
    return StepResult("\n".join(lines) or "no in-scope object URL", findings)


def run_injection(task, client):
    base = url_for(client, "/rest/products/search")
    if not base:
        return StepResult("product search is outside the signed charter", [])
    baseline = client.send("GET", base + "?" + urlencode({"q": SQLI_BASELINE}), intent=task["intent"])
    injected = client.send("GET", base + "?" + urlencode({"q": SQLI_PAYLOAD}), intent=task["intent"])
    findings, lines = [], []
    for exchange in (baseline, injected):
        found, text = observe(client, exchange)
        findings.extend(found)
        lines.append(text)
    base_count, inj_count = row_count(baseline.body), row_count(injected.body)
    counts_differ = base_count is not None and inj_count is not None and inj_count > base_count
    errored = injected.status >= 500 and baseline.status == 200 and any(
        word in injected.body.lower() for word in ("sqlite", "syntax", "sql"))
    if (counts_differ or errored) and not injected.blocked:
        if counts_differ:
            evidence = (f"A search for an absent name returned {base_count} rows. "
                        f"Breaking out of the LIKE predicate returned {inj_count} rows.")
        else:
            evidence = "The baseline search returned HTTP 200 and the break-out query produced a database error."
        stored = client.keep(injected, make_finding(
            "SQL injection in product search", "High", evidence,
            "The search term is concatenated into the query, so a caller can change which rows it returns.",
            "Compare a search for an absent name with a value that closes the LIKE string, on the approved origin.",
            "Bind the search term as a parameter. Do not concatenate it into the SQL statement.",
            proven=True, check="injection", endpoint="/rest/products/search"))
        if stored:
            findings.append(stored)
            lines.append(f"finding: {stored['title']} proven=true run={stored['run_id']}")
    return StepResult("\n".join(lines), findings)


def run_mass_assignment(task, client):
    register_url = url_for(client, "/api/Users")
    login_url = url_for(client, "/rest/user/login")
    who_url = url_for(client, "/rest/user/whoami")
    if not register_url or not login_url or not who_url:
        return StepResult("registration is outside the signed charter", [])
    email = f"charter-role-{secrets.token_hex(4)}@juice-sh.op"
    password = "Lab-" + secrets.token_hex(8)
    created = client.send("POST", register_url, body={
        "email": email, "password": password, "passwordRepeat": password, "role": "admin",
        "securityQuestion": {"id": 1}, "securityAnswer": secrets.token_hex(4)}, intent=task["intent"])
    logged = client.send("POST", login_url, body={"email": email, "password": password}, intent=task["intent"])
    who = client.send("GET", who_url, use_session=True, intent=task["intent"]) if client.identity.get("token") else None
    findings, lines = [], []
    for exchange in (created, logged, who):
        found, text = observe(client, exchange)
        findings.extend(found)
        if text:
            lines.append(text)
    if who is not None and not who.blocked and role_name(who.body) == "admin":
        stored = client.keep(who, make_finding(
            "Mass assignment grants administrator role", "High",
            f"The account {email} was created with an extra role field and the session reports role admin.",
            "A registrant can choose a privileged role by adding it to the registration body.",
            "Register on the approved origin with an extra role field and read the resulting session.",
            "Ignore role, privilege, and owner fields submitted by the client. Assign those on the server.",
            proven=True, check="mass-assignment", endpoint="/api/Users"))
        if stored:
            findings.append(stored)
            lines.append(f"finding: {stored['title']} proven=true run={stored['run_id']}")
    return StepResult("\n".join(lines), findings)


def run_misconfig(task, client):
    return discover(task, client, ("/metrics", "/ftp", "/rest/admin/application-configuration", "/"))


def run_api(task, client):
    check = task.get("check")
    if check in {"inventory"}:
        return discover(task, client, API_PATHS)
    if check == "misconfig":
        return run_misconfig(task, client)
    if check == "auth-setup":
        return run_auth_setup(task, client)
    if check == "bola":
        return run_bola(task, client)
    if check == "injection":
        return run_injection(task, client)
    if check == "mass-assignment":
        return run_mass_assignment(task, client)
    return StepResult("unknown api-top10 check", [])


def _sensitive_env(name):
    upper = name.upper()
    return upper in {"CHARTER_LLM_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "PGPASSWORD"} or upper.endswith(
        ("_API_KEY", "_PASSWORD", "_SECRET", "_TOKEN"))


def tool_env(proxy):
    env = {key: value for key, value in os_environ().items() if not _sensitive_env(key)}
    env["HTTP_PROXY"] = proxy
    env["HTTPS_PROXY"] = proxy
    env["http_proxy"] = proxy
    env["https_proxy"] = proxy
    env["NO_PROXY"] = ""
    env["no_proxy"] = ""
    return env


def os_environ():
    import os
    return os.environ


def tool_timeout():
    import os
    try:
        value = int(os.environ.get("CHARTER_TOOL_TIMEOUT", "180"))
    except ValueError:
        value = 180
    return max(1, value)


def run_command(argv, client):
    try:
        completed = subprocess.run(argv, capture_output=True, timeout=tool_timeout(),
                                   env=tool_env(client.proxy), check=False)
    except subprocess.TimeoutExpired:
        return StepResult(f"{Path(argv[0]).name} timed out before it finished", [])
    except OSError as exc:
        return StepResult(f"{Path(argv[0]).name} could not start ({type(exc).__name__})", [])
    output = (completed.stdout + b"\n" + completed.stderr).decode("utf-8", "replace")
    from .framing import preview
    return StepResult(f"{Path(argv[0]).name} exit {completed.returncode}\n{preview(output, 4000)}", [])


def _words(values):
    clean = []
    for word in values or DEFAULT_WORDS:
        if not isinstance(word, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,40}", word):
            continue
        if word in {".", ".."} or ".." in word:
            continue
        if word not in clean:
            clean.append(word)
    return clean[:40]


def run_ffuf(task, client):
    url = task["url"]
    if url.count("FUZZ") != 1:
        return StepResult("ffuf url must contain one FUZZ marker", [])
    allowed = []
    origin_refusal = None
    for word in _words(task.get("wordlist")):
        concrete = url.replace("FUZZ", word)
        try:
            client.enforce(concrete)
        except Refused as exc:
            if fatal_scope(str(exc)):
                raise
            if origin_refusal is None and "allow rule" in str(exc):
                origin_refusal = exc
            continue
        allowed.append((word, concrete))
    if origin_refusal and not allowed:
        client.store.note_block(client.campaign_id, url, str(origin_refusal), task["intent"])
        return StepResult(f"refused before send: {origin_refusal}", [])
    if not allowed:
        return StepResult("no in-scope paths in the wordlist", [])
    binary = shutil.which("ffuf")
    if not binary:
        findings, lines = [], [f"ffuf is not installed; requested {len(allowed)} in-scope paths through the capture proxy"]
        for _word, concrete in allowed:
            found, text = observe(client, client.send("GET", concrete, intent=task["intent"]))
            findings.extend(found)
            lines.append(text)
        return StepResult("\n".join(lines), findings)
    with TemporaryDirectory() as tmp:
        words = Path(tmp) / "words.txt"
        words.write_text("\n".join(word for word, _url in allowed) + "\n", encoding="ascii")
        argv = [binary, "-u", url, "-w", str(words), "-x", client.proxy, "-t", "1", "-rate", "1",
                "-mc", "200,201,204,301,302,307,401,403,500", "-of", "json",
                "-o", str(Path(tmp) / "out.json"), "-noninteractive"]
        if client.campaign_id:
            argv.extend(["-H", f"X-Charter-Campaign: {client.campaign_id}"])
        return run_command(argv, client)


def run_nuclei(task, client):
    refused = _guard(client, task["url"], task["intent"])
    if refused:
        return refused
    binary = shutil.which("nuclei")
    if not binary:
        return StepResult("nuclei is not installed; no requests were sent by this worker", [])
    argv = [binary, "-target", task["url"], "-proxy", client.proxy, "-jsonl", "-silent",
            "-rate-limit", "1", "-timeout", "10", "-disable-update-check"]
    if client.campaign_id:
        argv.extend(["-H", f"X-Charter-Campaign: {client.campaign_id}"])
    return run_command(argv, client)


def run_sqlmap(task, client):
    refused = _guard(client, task["url"], task["intent"])
    if refused:
        return refused
    if "?" not in task["url"]:
        return StepResult("sqlmap needs an in-scope URL with a query parameter", [])
    binary = shutil.which("sqlmap")
    if not binary:
        return StepResult("sqlmap is not installed; no requests were sent by this worker", [])
    with TemporaryDirectory() as tmp:
        argv = [binary, "-u", task["url"], "--batch", "--proxy", client.proxy, "--delay", "1",
                "--threads", "1", "--technique", "BEUST", "--flush-session", "--output-dir", tmp]
        if client.campaign_id:
            argv.extend(["--header", f"X-Charter-Campaign: {client.campaign_id}"])
        return run_command(argv, client)


def run_zap(task, client):
    refused = _guard(client, task["url"], task["intent"])
    if refused:
        return refused
    binary = shutil.which("zap-baseline.py")
    if not binary:
        return StepResult("zap-baseline.py is not installed; no requests were sent by this worker", [])
    parts = urlsplit(client.proxy)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    argv = [binary, "-t", task["url"], "-I", "-m", "1", "-z",
            f"-config network.connection.httpProxy.enabled=true "
            f"-config network.connection.httpProxy.host={parts.hostname} "
            f"-config network.connection.httpProxy.port={port}"]
    return run_command(argv, client)


WORKERS = {
    "http": run_http,
    "recon": run_recon,
    "api-top10": run_api,
    "ffuf": run_ffuf,
    "nuclei": run_nuclei,
    "zap": run_zap,
    "sqlmap": run_sqlmap,
}


def execute(task, client):
    fn = WORKERS.get(task.get("worker"))
    if fn is None:
        return StepResult("unknown worker refused", [])
    return fn(task, client)
