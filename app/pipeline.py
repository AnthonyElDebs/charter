"""Run the coverage matrix from the ledger. This step does not call the model."""
import os
from urllib.parse import urlsplit

from .workers import StepResult, execute


FILE_PARAMS = {"file", "path", "page", "template", "doc", "folder", "dir", "include", "document", "download", "item"}
URL_PARAMS = {"url", "uri", "dest", "target", "fetch", "site", "host", "domain", "endpoint", "callback"}
REDIRECT_PARAMS = {"next", "redirect", "return", "goto", "continue", "dest", "destination", "rurl", "url",
                   "returnurl", "redirecturl"}
SITE_CHECKS = ("misconfig", "secrets", "cors", "jwt", "auth-session", "idor")


def recon_cap():
    try:
        value = int(os.environ.get("CHARTER_MAX_RECON", "2"))
    except (TypeError, ValueError):
        value = 2
    return min(4, max(1, value))


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
    for row in candidates[:12]:
        sample = row.get("sample") or ""
        if row["params"] and sample:
            for check in ("sqli", "xss-reflected"):
                _run(client, ledger, {"worker": "coverage", "check": check, "intent": intent,
                                      "url": sample, "params": list(row["params"])}, findings, lines)
            file_names = [name for name in row["params"] if name.lower() in FILE_PARAMS]
            url_names = [name for name in row["params"] if name.lower() in URL_PARAMS]
            redirect_names = [name for name in row["params"] if name.lower() in REDIRECT_PARAMS]
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
    samples = []
    for row in ledger.endpoints.values():
        if row.get("sample") and row["sample"] not in samples:
            samples.append(row["sample"])
    for url in samples[:3]:
        _run(client, ledger, {"worker": "sqlmap", "intent": intent, "url": url}, findings, lines)
        _run(client, ledger, {"worker": "nuclei", "intent": intent, "url": url}, findings, lines)
    if origin:
        _run(client, ledger, {"worker": "zap", "intent": intent, "url": origin.split("?", 1)[0]}, findings, lines)
    proven = sorted({item.get("check") for item in findings if item.get("proven") and item.get("check")})
    summary = "Coverage matrix finished."
    if proven:
        summary += " Proven: " + ", ".join(proven) + "."
    summary += " Do not repeat recon."
    return StepResult(summary + ("\n" + "\n".join(lines) if lines else ""), findings)
