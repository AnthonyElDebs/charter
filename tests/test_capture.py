from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from uuid import uuid4

from mitmproxy import http
from mitmproxy.test import tflow

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
