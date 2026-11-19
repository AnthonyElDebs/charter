"""Run the coverage matrix from the ledger. This step does not call the model."""
import os
import re
from urllib.parse import urlsplit

from .workers import StepResult, execute


FILE_PARAMS = {"file", "path", "page", "template", "doc", "folder", "dir", "include", "document", "download", "item",
               "filename", "filepath", "templatefile"}
URL_PARAMS = {"url", "uri", "dest", "target", "fetch", "site", "host", "domain", "endpoint", "callback", "webhook"}
REDIRECT_PARAMS = {"next", "redirect", "return", "goto", "continue", "dest", "destination", "rurl", "url", "uri",
                   "returnurl", "redirecturl", "returl", "redirecturi", "returnto", "nexturl", "redir", "forward",
                   "view", "checkouturl", "continueurl"}
SITE_CHECKS = ("misconfig", "secrets", "cors", "jwt", "auth-session", "idor")


def _compact(name):
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def looks_redirect(name):
    low = _compact(name)
    if low in REDIRECT_PARAMS:
        return True
    return any(hint in low for hint in ("redirect", "returl", "returnurl", "returnto", "nexturl"))


def looks_file(name):
    low = _compact(name)
    if low in FILE_PARAMS:
        return True
    return any(hint in low for hint in ("file", "template", "folder", "include", "document", "download"))


def looks_url(name):
    low = _compact(name)
    if low in {"url", "uri", "dest", "target", "callback", "webhook", "endpoint"}:
        return True
    if looks_redirect(name):
        return False
    return low in URL_PARAMS or any(hint in low for hint in ("callback", "webhook", "fetchurl"))


def recon_cap():
    try:
        value = int(os.environ.get("CHARTER_MAX_RECON", "2"))
    except (TypeError, ValueError):
        value = 2
    return min(2, max(1, value))


def followup_cap():
    try:
        value = int(os.environ.get("CHARTER_MAX_FOLLOWUPS", "3"))
    except (TypeError, ValueError):
        value = 3
    return min(4, max(0, value))


def _origin(client):
    raw = client.target or ""
    if not raw and client.charter.get("allow"):
        raw = client.charter["allow"][0]
    parts = urlsplit(raw)
    if parts.scheme and parts.netloc:
        return f"{parts.scheme}://{parts.netloc}/"
    return raw


def _run(client, ledger, task, findings, lines):
    path = urlsplit(task.get("url") or "").path or "/"
    ident = task.get("check") or task.get("worker")
    if ledger.attempted(path, ident):
        return
    result = execute(task, client)
    outcome = "proven" if any(item.get("proven") for item in result.findings) else "checked"
    ledger.mark(path, ident, outcome)
    findings.extend(result.findings)
    if result.observation:
        lines.append(result.observation.split("\n", 1)[0][:180])


def run_pipeline(client):
    """One pass over discovered parameters and forms. Later calls do not repeat it."""
    ledger = client.ledger
    if ledger is None or ledger.pipeline_done:
        return StepResult("coverage matrix already finished", [])
    ledger.pipeline_done = True
    intent = "coverage matrix on discovered endpoints"
    findings, lines = [], []
    origin = _origin(client)
    for check in SITE_CHECKS:
        _run(client, ledger, {"worker": "coverage", "check": check, "intent": intent, "url": origin}, findings, lines)
    candidates = [row for row in ledger.endpoints.values() if row["params"] or row["forms"]]
    sample_url = ""
    for row in candidates[:40]:
        sample = row.get("sample") or ""
        if row["params"] and sample:
            if not sample_url and "?" in sample:
                sample_url = sample
            for check in ("sqli", "xss-reflected"):
                _run(client, ledger, {"worker": "coverage", "check": check, "intent": intent,
                                      "url": sample, "params": list(row["params"])}, findings, lines)
            file_names = [name for name in row["params"] if looks_file(name)]
            url_names = [name for name in row["params"] if looks_url(name)]
            redirect_names = [name for name in row["params"] if looks_redirect(name)]
            if file_names:
                _run(client, ledger, {"worker": "coverage", "check": "traversal", "intent": intent,
                                      "url": sample, "params": file_names}, findings, lines)
            if url_names:
                _run(client, ledger, {"worker": "coverage", "check": "ssrf", "intent": intent,
                                      "url": sample, "params": url_names}, findings, lines)
            if redirect_names:
                _run(client, ledger, {"worker": "coverage", "check": "open-redirect", "intent": intent,
                                      "url": sample, "params": redirect_names}, findings, lines)
        for form in row["forms"]:
            if form.get("method") not in {"POST", "PUT", "PATCH", "DELETE"}:
                continue
            _run(client, ledger, {"worker": "coverage", "check": "xss-stored", "intent": intent,
                                  "url": row["url"], "forms": [form]}, findings, lines)
            _run(client, ledger, {"worker": "coverage", "check": "csrf", "intent": intent,
                                  "url": row["url"], "forms": [form]}, findings, lines)
    if sample_url:
        _run(client, ledger, {"worker": "sqlmap", "intent": intent, "url": sample_url}, findings, lines)
        _run(client, ledger, {"worker": "nuclei", "intent": intent, "url": sample_url.split("?", 1)[0]}, findings, lines)
    if origin:
        _run(client, ledger, {"worker": "zap", "intent": intent, "url": origin.split("?", 1)[0]}, findings, lines)
    ledger.mark("/", "sweep", "checked")
    proven = sorted({item.get("check") for item in findings if item.get("proven") and item.get("check")})
    summary = "Coverage matrix finished."
    if proven:
        summary += " Proven: " + ", ".join(proven) + "."
    summary += " Do not repeat recon."
    return StepResult(summary + ("\n" + "\n".join(lines) if lines else ""), findings)
