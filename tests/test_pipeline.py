"""The coverage matrix uses discovered parameters and does not repeat recon."""
import json
import time
from pathlib import Path
from subprocess import CompletedProcess
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
import unittest

import httpx

import lab
from app.exchange import Client
from app.governor import Governor
from app.ledger import Ledger
from app.loop import run_campaign
from app.worker_config import TARGET
from app.workers import execute
from tests.fakes import MemoryStore


def quiet(turns=4, requests=300):
    return Governor(turns, requests, 20000, 0, monotonic_fn=lambda: 0, sleep_fn=lambda _seconds: None)


class Asp:
    """Classic ASP stand-in: MSSQL and MySQL errors, reflected and stored XSS, traversal, redirect, CSRF."""

    def __init__(self, store):
        self.store = store
        self.urls = []
        self.comments = []
        self.delay = 0

    def transport(self):
        return httpx.MockTransport(self.handle)

    def handle(self, request):
        self.urls.append(str(request.url))
        parts = urlsplit(str(request.url))
        path = "/" if parts.path in {"", "/"} else parts.path
        query = parse_qs(parts.query)
        if self.delay and any(token in parts.query for token in ("WAITFOR", "SLEEP")):
            time.sleep(self.delay)
        if path == "/comment" and request.method.upper() == "POST":
            self.comments.append(request.content.decode("utf-8", "replace"))
            return self._send(200, "stored", "text/plain")
        if path == "/comment":
            return self._send(200, "<html>" + "\n".join(self.comments) + "</html>", "text/html")
        if path == "/showthread.asp":
            value = query.get("id", [""])[0]
            if "'" in value:
                body = ("Microsoft OLE DB Provider for SQL Server error '80040e14' "
                        "Unclosed quotation mark after the character string. Incorrect syntax near.")
                return self._send(500, body, "text/plain")
            return self._send(200, "thread ok", "text/plain")
        if path == "/showforum.asp":
            value = query.get("id", [""])[0]
            if "'" in value:
                return self._send(500, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version", "text/plain")
            return self._send(200, "forum ok", "text/plain")
        if path == "/Templatize.asp":
            value = query.get("item", [""])[0]
            if "charterxss" in value:
                return self._send(200, f"<html>result {value}</html>", "text/html")
            return self._send(200, "template", "text/plain")
        if path == "/download.asp":
            value = query.get("file", [""])[0]
            if "etc/passwd" in value:
                return self._send(200, "root:x:0:0:root:/root:/bin/sh\n", "text/plain")
            return self._send(200, "readme", "text/plain")
        if path == "/go.asp":
            target = query.get("next", [""])[0]
            if target.startswith("http"):
                return self._send(302, "", "text/plain", {"Location": target})
            return self._send(200, "stay", "text/plain")
        if path == "/Login.asp":
            target = query.get("RetURL", [""])[0]
            if target.startswith("http"):
                return self._send(302, "", "text/plain", {"Location": target})
            return self._send(200, "login", "text/html")
        if path == "/Jump.asp":
            target = query.get("RetURL", [""])[0]
            decoded = target.replace("%2F", "/").replace("%2f", "/")
            if "example.invalid" in decoded and not target.startswith("https://"):
                page = f'<html><meta http-equiv="refresh" content="0;url={decoded}"></html>'
                return self._send(200, page, "text/html")
            return self._send(200, "stay", "text/html")
        if path == "/Search.asp":
            value = query.get("tfSearch", [""])[0]
            return self._send(200, f"<html>results {value}</html>", "text/html")
        if path == "/Safe.asp":
            value = query.get("q", [""])[0].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            return self._send(200, f"<html>{value}</html>", "text/html")
        if path == "/fetch.asp":
            value = query.get("url", [""])[0]
            if "robots.txt" in value:
                return self._send(200, "User-agent: *\nDisallow: /private\n", "text/plain")
            return self._send(200, "local", "text/plain")
        if path == "/win.asp":
            value = query.get("file", [""])[0]
            if "boot.ini" in value.lower():
                return self._send(200, "[boot loader]\ntimeout=30\n", "text/plain")
            return self._send(200, "no file", "text/plain")
        if path == "/clock.asp":
            return self._send(200, "clock", "text/plain")
        if path == "/product.asp":
            value = query.get("id", [""])[0]
            if "AND 1=1" in value or value == "1":
                return self._send(200, "product " + ("alpha " * 30), "text/plain")
            if "AND 1=2" in value:
                return self._send(200, "none", "text/plain")
            return self._send(200, "product " + ("alpha " * 30), "text/plain")
        if path == "/help.html":
            return self._send(200, "<html>help</html>", "text/html")
        if path == "/":
            page = """<html>
            <a href="/showthread.asp?id=0">thread</a>
            <a href="/showforum.asp?id=0">forum</a>
            <a href="/Templatize.asp?item=html">item</a>
            <a href="/download.asp?file=readme.txt">file</a>
            <a href="/go.asp?next=home">go</a>
            <a href="/Login.asp?RetURL=/home.asp">login</a>
            <a href="/fetch.asp?url=/robots.txt">fetch</a>
            <a href="http://evil.example/steal?id=1">off</a>
            <form method="get" action="/Search.asp"><input name="tfSearch"></form>
            <form method="post" action="/comment"><input name="comment"></form>
            </html>"""
            return self._send(200, page, "text/html")
        return self._send(404, "missing", "text/plain")

    def _send(self, status, body, content_type="application/json", extra=None):
        from uuid import uuid4
        run_id = str(uuid4())
        self.store.add_run(run_id, {"response": {"status": status, "body": body}})
        headers = {"Content-Type": content_type, "X-Charter-Run": run_id}
        if extra:
            headers.update(extra)
        return httpx.Response(status, content=body.encode(), headers=headers)


class Script:
    def __init__(self):
        self.messages = []

    def complete(self, system, user):
        self.messages.append(user)
        return json.dumps({"summary": "map again", "tasks": [
            {"worker": "recon", "intent": "Discover paths, forms, and parameters"},
            {"worker": "coverage", "check": "idor", "intent": "idor again"},
            {"worker": "coverage", "check": "csrf", "intent": "csrf again"},
            {"worker": "coverage", "check": "open-redirect", "intent": "redirect again"},
        ]}), 5


class PipelineTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / "approved"
        lab.approve(Path(temp.name), "test-fixture")
        self.store = MemoryStore()
        self.asp = Asp(self.store)
        self.client = Client(root=self.root, charter={"allow": [TARGET], "deny": [TARGET + "private"]},
                             store=self.store, governor=quiet(), transport=self.asp.transport(),
                             campaign_id="campaign", target=TARGET)
        self.client.ledger = Ledger()

    def test_direct_checks_bind_high_and_medium_findings(self):
        cases = [
            ("sqli", TARGET + "showthread.asp?id=0", ["id"], "High", "SQL error"),
            ("sqli", TARGET + "showforum.asp?id=0", ["id"], "High", "SQL error"),
            ("xss-reflected", TARGET + "Templatize.asp?item=html", ["item"], "High", "Reflected"),
            ("traversal", TARGET + "download.asp?file=readme.txt", ["file"], "High", "file outside"),
            ("open-redirect", TARGET + "go.asp?next=home", ["next"], "Medium", "Redirect"),
            ("xss-reflected", TARGET + "Search.asp?tfSearch=a", ["tfSearch"], "High", "Reflected"),
            ("open-redirect", TARGET + "Login.asp?RetURL=/home.asp", ["RetURL"], "Medium", "Redirect"),
            ("ssrf", TARGET + "fetch.asp?url=/robots.txt", ["url"], "High", "requested a URL"),
            ("traversal", TARGET + "win.asp?file=readme.txt", ["file"], "High", "file outside"),
        ]
        for check, url, params, severity, title in cases:
            result = execute({"worker": "coverage", "check": check, "intent": check, "url": url, "params": params},
                             self.client)
            proven = [item for item in result.findings if item.get("proven") and item.get("check") == check]
            self.assertTrue(proven, result.observation)
            self.assertEqual(proven[0]["severity"], severity)
            self.assertIn(title, proven[0]["title"])
            self.assertTrue(proven[0].get("run_id"))
            self.assertTrue(proven[0].get("remediation"))
        form = {"method": "POST", "action": TARGET + "comment", "fields": [{"name": "comment", "type": "text"}]}
        stored = execute({"worker": "coverage", "check": "xss-stored", "intent": "store",
                          "url": TARGET, "forms": [form]}, self.client)
        csrf = execute({"worker": "coverage", "check": "csrf", "intent": "csrf",
                        "url": TARGET, "forms": [form]}, self.client)
        stored_hit = [item for item in stored.findings if item.get("proven") and item.get("check") == "xss-stored"]
        csrf_hit = [item for item in csrf.findings if item.get("proven") and item.get("check") == "csrf"]
        self.assertEqual(stored_hit[0]["severity"], "High")
        self.assertEqual(csrf_hit[0]["severity"], "Medium")
        self.assertTrue(stored_hit[0]["run_id"] and csrf_hit[0]["run_id"])
        encoded = execute({"worker": "coverage", "check": "xss-reflected", "intent": "encoded",
                           "url": TARGET + "Safe.asp?q=1", "params": ["q"]}, self.client)
        self.assertFalse(any(item.get("proven") for item in encoded.findings))
        jumped = execute({"worker": "coverage", "check": "open-redirect", "intent": "meta",
                          "url": TARGET + "Jump.asp?RetURL=/home.asp", "params": ["RetURL"]}, self.client)
        jump_hit = [item for item in jumped.findings if item.get("proven") and item.get("check") == "open-redirect"]
        self.assertTrue(jump_hit and jump_hit[0]["severity"] == "Medium" and jump_hit[0].get("run_id"))

    def test_boolean_and_time_sqli_when_there_is_no_error_string(self):
        boolean = execute({"worker": "coverage", "check": "sqli", "intent": "boolean",
                           "url": TARGET + "product.asp?id=1", "params": ["id"]}, self.client)
        self.assertTrue(any(item.get("title") == "Boolean SQL condition changes the response" and item.get("proven")
                            for item in boolean.findings))
        self.asp.delay = 0.12
        import os
        previous = os.environ.get("CHARTER_SQLI_SLEEP")
        os.environ["CHARTER_SQLI_SLEEP"] = "0.08"
        try:
            timed = execute({"worker": "coverage", "check": "sqli", "intent": "time",
                             "url": TARGET + "clock.asp?id=1", "params": ["id"]}, self.client)
        finally:
            if previous is None:
                os.environ.pop("CHARTER_SQLI_SLEEP", None)
            else:
                os.environ["CHARTER_SQLI_SLEEP"] = previous
        self.assertFalse(any(item.get("title") == "Boolean SQL condition changes the response" for item in timed.findings))
        self.assertTrue(any(item.get("title") == "Delayed SQL statement changes the response time" and item.get("proven")
                            and item.get("run_id") for item in timed.findings), timed.observation)

    def test_campaign_runs_the_matrix_once_and_refuses_another_host(self):
        script = Script()
        result = run_campaign("Prove injection.", root=self.root, store=self.store, llm=script, lab=True,
                              governor=quiet(), charter={"allow": [TARGET], "deny": [TARGET + "private"]},
                              transport=self.asp.transport(), target=TARGET)
        self.assertEqual(result.state, "proven")
        self.assertNotIn("turn budget", result.reason)
        self.assertLessEqual(len(script.messages), 4)
        self.assertIn('"mapped": true', script.messages[0])
        self.assertIn('"pipeline_done": true', script.messages[0])
        extra = self.store.campaigns[result.campaign_id]["extra"]
        self.assertLessEqual(extra["recon_turns"], 2)
        self.assertGreaterEqual(extra["recon_turns"], 1)
        recon_hits = [url for url in self.asp.urls if url.endswith("/showthread.asp?id=0")]
        self.assertEqual(recon_hits, [TARGET + "showthread.asp?id=0"])
        quotes = [url for url in self.asp.urls if "showthread.asp" in url and "charterbase" in url and ("'" in url or "%27" in url)]
        self.assertEqual(len(quotes), 1)
        self.assertEqual(len([url for url in self.asp.urls if url.rstrip("/").endswith("/api/items/1")]), 1)
        self.assertFalse(any("evil.example" in url for url in self.asp.urls))
        self.assertTrue(any(item.get("check") == "sqli" and item.get("severity") == "High" and item.get("proven")
                            for item in result.findings))
        self.assertTrue(any(item.get("check") == "xss-reflected" and item.get("proven") for item in result.findings))
        self.assertTrue(any(item.get("check") == "xss-stored" and item.get("proven") for item in result.findings))
        self.assertTrue(any(item.get("check") == "traversal" and item.get("proven") for item in result.findings))
        self.assertTrue(any(item.get("check") == "open-redirect" and item.get("severity") == "Medium"
                            for item in result.findings))
        self.assertTrue(any(item.get("check") == "csrf" and item.get("proven") for item in result.findings))
        self.assertTrue(any(item.get("check") == "ssrf" and item.get("severity") == "High" and item.get("proven")
                            for item in result.findings))
        search = [item for item in result.findings if item.get("check") == "xss-reflected" and item.get("proven")]
        self.assertTrue(any(item.get("endpoint") == "/Search.asp" for item in search))
        redirects = [item for item in result.findings if item.get("check") == "open-redirect" and item.get("proven")]
        self.assertTrue(any(item.get("endpoint") == "/Login.asp" for item in redirects))
        headers = [item for item in result.findings if item.get("title") == "Response is missing browser security headers"]
        self.assertEqual(len(headers), 1)
        before = list(self.asp.urls)
        refused = execute({"worker": "coverage", "check": "sqli", "intent": "outside",
                           "url": "http://evil.example/showthread.asp?id=1", "params": ["id"]}, self.client)
        self.assertFalse(any(item.get("proven") for item in refused.findings))
        self.assertEqual(self.asp.urls, before)

    def test_sqlmap_vulnerable_output_is_bound_to_an_exchange(self):
        completed = CompletedProcess(args=["sqlmap"], returncode=0,
                                     stdout=b"sqlmap identified the following injection point\nParameter: id (GET)\n    Type: error-based\n[INFO] GET parameter 'id' is vulnerable.\n",
                                     stderr=b"")
        with patch("app.workers.shutil.which", return_value="/usr/bin/sqlmap"), \
             patch("app.workers.subprocess.run", return_value=completed):
            result = execute({"worker": "sqlmap", "intent": "confirm", "url": TARGET + "showthread.asp?id=1"},
                             self.client)
        proven = [item for item in result.findings if item.get("check") == "sqli" and item.get("proven")]
        self.assertTrue(proven and proven[0].get("run_id") and proven[0]["severity"] == "High")


if __name__ == "__main__":
    unittest.main()
