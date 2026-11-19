"""Coverage checks against a scripted origin. The charter is still enforced before each send."""
import base64
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import parse_qs, urlsplit
import unittest

import httpx

import lab
from app.exchange import Client
from app.governor import Governor
from app.workers import execute, run_auth_setup
from app.worker_config import TARGET
from tests.fakes import MemoryStore


def quiet_governor():
    return Governor(8, 200, 5000, 0, monotonic_fn=lambda: 0, sleep_fn=lambda _seconds: None)


class Surface:
    def __init__(self, store):
        self.store = store
        self.urls = []
        self.comments = []

    def transport(self):
        return httpx.MockTransport(self.handle)

    def handle(self, request):
        self.urls.append(str(request.url))
        parts = urlsplit(str(request.url))
        path = "/" if parts.path in {"", "/"} else parts.path.rstrip("/")
        query = parse_qs(parts.query)
        if path == "/login" and request.method.upper() == "POST":
            return self._send(200, {"token": "operator-session-token"})
        if path == "/feedback" and request.method.upper() == "POST":
            raw = request.content.decode("utf-8", "replace")
            self.comments.append(raw)
            return self._send(200, "stored", "text/plain")
        if path == "/feedback":
            body = "<html>" + "\n".join(self.comments) + "</html>"
            return self._send(200, body, "text/html")
        if path == "/app.js":
            return self._send(200, 'const api_key = "abcd1234efgh";', "text/javascript")
        if path == "/.env":
            return self._send(200, "PASSWORD=kept-in-evidence\n", "text/plain")
        if path == "/.git/HEAD":
            return self._send(200, "ref: refs/heads/main\n", "text/plain")
        if path == "/api/profile":
            header = request.headers.get("authorization", "")
            token = header[7:] if header.lower().startswith("bearer ") else ""
            if self._alg(token) == "none":
                return self._send(200, {"email": "ada@example.test"})
            return self._send(401, {"error": "denied"})
        if path in {"/api/items/1", "/api/items/2"}:
            email = "one@example.test" if path.endswith("/1") else "two@example.test"
            return self._send(200, {"id": path[-1], "email": email})
        if "file" in query and "etc/passwd" in query["file"][0]:
            return self._send(200, "root:x:0:0:root:/root:/bin/sh\n", "text/plain")
        if "url" in query and "robots.txt" in query["url"][0]:
            return self._send(200, "User-agent: *\nDisallow: /private\n", "text/plain")
        if "next" in query:
            return self._send(302, "", "text/plain", {"Location": query["next"][0]})
        value = query.get("q", [""])[0]
        if value.endswith("'"):
            return self._send(500, "sqlite syntax error near quote", "text/plain")
        if "$(" in value and "printf" in value:
            marker = value.split("cmd", 1)[-1].rstrip(")")
            return self._send(200, f"chartercmd{marker}", "text/plain")
        if "charterxss" in value:
            return self._send(200, f"<html>result {value}</html>", "text/html")
        if path == "/":
            page = "<html><form method=\"post\" action=\"/feedback\"><input name=\"comment\"></form>" \
                   "<script src=\"/app.js\"></script></html>"
            extra = {"Set-Cookie": "session=abc12345; Path=/"}
            origin = request.headers.get("origin")
            if origin:
                extra["Access-Control-Allow-Origin"] = origin
                extra["Access-Control-Allow-Credentials"] = "true"
            return self._send(200, page, "text/html", extra)
        if request.headers.get("origin"):
            return self._send(200, "ok", "text/plain", {
                "Access-Control-Allow-Origin": request.headers["origin"],
                "Access-Control-Allow-Credentials": "true",
            })
        return self._send(404, "missing", "text/plain")

    def _alg(self, token):
        try:
            header = token.split(".", 1)[0]
            pad = "=" * (-len(header) % 4)
            return json.loads(base64.urlsafe_b64decode(header + pad)).get("alg")
        except (json.JSONDecodeError, ValueError, TypeError):
            return ""

    def _send(self, status, body, content_type="application/json", extra=None):
        from uuid import uuid4
        run_id = str(uuid4())
        raw = body if isinstance(body, str) else json.dumps(body)
        self.store.add_run(run_id, {"response": {"status": status, "body": raw}})
        headers = {"Content-Type": content_type, "X-Charter-Run": run_id}
        if extra:
            headers.update(extra)
        return httpx.Response(status, content=raw.encode(), headers=headers)


class CoverageTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        lab.approve(self.folder, "test-fixture")
        self.store = MemoryStore()
        self.surface = Surface(self.store)
        self.client = Client(root=self.folder / "approved", charter={"allow": [TARGET], "deny": [TARGET + "private"]},
                             store=self.store, governor=quiet_governor(), transport=self.surface.transport(),
                             campaign_id="campaign", target=TARGET)

    def _proven(self, check):
        result = execute({"worker": "coverage", "check": check, "intent": f"test {check}"}, self.client)
        proven = [item for item in result.findings if item.get("proven") and item.get("check") == check]
        self.assertTrue(proven, result.observation)
        self.assertTrue(all(item.get("run_id") and item.get("remediation") and item.get("severity") for item in proven))
        return result

    def test_reflected_and_stored_xss(self):
        self._proven("xss-reflected")
        self._proven("xss-stored")

    def test_injection_traversal_ssrf_and_redirect(self):
        self._proven("sqli")
        self._proven("command-injection")
        self._proven("traversal")
        self._proven("ssrf")
        self._proven("open-redirect")

    def test_browser_and_exposure_checks(self):
        self._proven("cors")
        self._proven("csrf")
        self._proven("misconfig")
        self._proven("secrets")
        self._proven("auth-session")
        self._proven("idor")

    def test_jwt_alg_none_is_bound_to_evidence(self):
        self.client.identity["token"] = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"
        result = self._proven("jwt")
        self.assertNotIn(self.client.identity["token"], result.observation)

    def test_operator_login_keeps_the_password_out_of_the_observation(self):
        self.client.credentials = {"username": "ada@example.test", "password": "Lab-secret-99", "login_url": TARGET + "login"}
        result = run_auth_setup({"intent": "sign in"}, self.client)
        self.assertIn("Authenticated with the operator account", result.observation)
        self.assertNotIn("Lab-secret-99", result.observation)
        self.assertNotIn("operator-session-token", result.observation)
        self.assertEqual(self.client.identity.get("token"), "operator-session-token")

    def test_coverage_does_not_request_a_host_outside_the_charter(self):
        self.client.target = "http://evil.example/"
        before = list(self.surface.urls)
        result = execute({"worker": "coverage", "check": "xss-reflected", "intent": "outside"}, self.client)
        self.assertFalse(any(item.get("proven") for item in result.findings))
        self.assertEqual(self.surface.urls, before)
        self.assertTrue(self.store.blocks)

    def test_sweep_records_several_proven_classes(self):
        result = execute({"worker": "coverage", "check": "sweep", "intent": "full pass"}, self.client)
        checks = {item.get("check") for item in result.findings if item.get("proven")}
        self.assertGreaterEqual(len(checks), 4)


if __name__ == "__main__":
    unittest.main()
