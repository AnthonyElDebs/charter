from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from uuid import uuid4

from mitmproxy import http
from mitmproxy.test import tflow

import os

import lab
from app.capture import Gate
from app.evidence import assess, capture
from app.reports import pdf, templates, exchange_text
from app.worker_config import TARGET


class CaptureTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        self.gate = Gate(self.folder / "approved")
        self.flow = tflow.tflow()
        self.flow.request = http.Request.make("GET", TARGET, headers={"Host": "juice-shop:3000"})

    @patch("app.capture.storage.begin", return_value="demo-id")
    def test_no_approval_denies_before_upstream(self, begin):
        self.gate.requestheaders(self.flow)
        self.assertEqual(self.flow.response.status_code, 403)
        self.assertFalse(self.gate.approved_clients)
        self.assertFalse(begin.call_args.args[1])

    @patch("app.capture.storage.begin", return_value="demo-id")
    def test_signed_capture_and_reports(self, begin):
        lab.approve(self.folder, "test-fixture")
        self.gate.requestheaders(self.flow)
        self.assertIsNone(self.flow.response)
        self.assertEqual(self.flow.request.headers["connection"], "close")
        self.flow.response = http.Response.make(200, b"<html><script>sample</script></html>",
                                               {"Content-Type":"text/html"})
        with patch("app.capture.storage.finish") as finish:
            self.gate.response(self.flow)
        run_id, evidence, finding = finish.call_args.args
        self.assertEqual(run_id, "demo-id")
        self.assertEqual(finding["severity"], "Low")
        self.assertNotIn("X-Charter-Run", dict(evidence["response"]["headers"]))
        self.assertEqual(self.flow.response.headers["X-Charter-Run"], "demo-id")
        run = dict(id=uuid4(), details=begin.call_args.args[0], state="complete",
                   started=datetime.now(timezone.utc), evidence=evidence, finding=finding, audit=[])
        self.assertTrue(pdf(run).startswith(b"%PDF-"))
        html = templates.get_template("detail.html").render(run=run, exchange=exchange_text(evidence),
                                                          exporting=True, css="")
        self.assertIn("&lt;script&gt;sample&lt;/script&gt;", html)
        self.assertIn(evidence["response"]["body_base64"], html)
        self.flow.response.headers["Content-Security-Policy"] = "default-src 'self'"
        self.assertIsNone(assess(capture(self.flow)))

    @patch("app.capture.storage.begin", side_effect=RuntimeError("unavailable"))
    def test_database_failure_retains_local_denial(self, begin):
        lab.approve(self.folder, "test-fixture")
        with self.assertRaises(RuntimeError):
            self.gate.requestheaders(self.flow)
        self.assertEqual(self.flow.response.status_code, 503)
        self.assertFalse(self.gate.approved_clients)

    @patch("app.capture.storage.begin", return_value="demo-id")
    def test_post_keeps_allowed_headers_and_records_the_campaign(self, begin):
        lab.approve(self.folder, "test-fixture")
        campaign = "11111111-1111-4111-8111-111111111111"
        self.flow.request = http.Request.make(
            "POST", TARGET, content=b'{"a":1}',
            headers={"Host": "juice-shop:3000", "Authorization": "Bearer demo",
                     "Content-Type": "application/json", "X-Charter-Campaign": campaign, "X-Evil": "no"})
        self.gate.requestheaders(self.flow)
        self.assertIsNone(self.flow.response)
        self.assertEqual(self.flow.request.headers["host"], "juice-shop:3000")
        self.assertEqual(self.flow.request.headers["authorization"], "Bearer demo")
        self.assertEqual(self.flow.request.headers["content-type"], "application/json")
        self.assertNotIn("x-charter-campaign", self.flow.request.headers)
        self.assertNotIn("x-evil", self.flow.request.headers)
        self.assertEqual(begin.call_args.args[0]["campaign_id"], campaign)
        self.assertTrue(self.flow.request.content.startswith(b"{"))

    @patch("app.capture.storage.begin", return_value="demo-id")
    def test_other_origins_denied_paths_and_rate_limit(self, begin):
        lab.approve(self.folder, "test-fixture")
        self.flow.request = http.Request.make("GET", "http://evil.test/")
        self.gate.requestheaders(self.flow)
        self.assertEqual(self.flow.response.status_code, 403)
        private = tflow.tflow()
        private.request = http.Request.make("GET", TARGET + "private")
        self.gate.requestheaders(private)
        self.assertEqual(private.response.status_code, 403)
        chunked = tflow.tflow()
        chunked.request = http.Request.make("POST", TARGET, content=b"a", headers={"Transfer-Encoding": "chunked"})
        self.gate.requestheaders(chunked)
        self.assertEqual(chunked.response.status_code, 403)
        self.gate.min_interval = 30
        first = tflow.tflow()
        first.request = http.Request.make("GET", TARGET)
        self.gate.requestheaders(first)
        self.assertIsNone(first.response)
        second = tflow.tflow()
        second.request = http.Request.make("GET", TARGET)
        self.gate.requestheaders(second)
        self.assertEqual(second.response.status_code, 403)
        self.assertEqual(second.response.headers["X-Charter-Reason"], "rate-limit")

    @patch("app.capture.storage.begin", return_value="demo-id")
    def test_custom_origin_is_forwarded(self, begin):
        lab.approve(self.folder, "test-fixture", target="http://app.test:8080/")
        self.flow.request = http.Request.make("GET", "http://app.test:8080/health")
        self.gate.requestheaders(self.flow)
        self.assertIsNone(self.flow.response)
        self.assertEqual(self.flow.request.headers["host"], "app.test:8080")

        class Server:
            def __init__(self, address):
                self.address = address
                self.error = None

        class Data:
            pass

        blocked = Data()
        blocked.client = self.flow.client_conn
        blocked.server = Server(("evil", 80))
        self.gate.server_connect(blocked)
        self.assertEqual(blocked.server.error, "Unapproved upstream connection")
        allowed = Data()
        allowed.client = self.flow.client_conn
        allowed.server = Server(("app.test", 8080))
        self.gate.server_connect(allowed)
        self.assertIsNone(allowed.server.error)

    @patch("app.capture.storage.begin", return_value="demo-id")
    def test_open_mode_forwards_without_a_charter(self, begin):
        os.environ["CHARTER_OPEN"] = "1"
        self.addCleanup(os.environ.pop, "CHARTER_OPEN", None)
        self.flow.request = http.Request.make("GET", "http://zero.webappsecurity.com/")
        self.gate.requestheaders(self.flow)
        self.assertIsNone(self.flow.response)
        self.assertEqual(self.flow.request.headers["host"], "zero.webappsecurity.com")
        self.assertTrue(begin.call_args.args[1])
