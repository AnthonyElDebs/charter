import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import lab
from app.web import app
from app.worker_config import TARGET


class WebTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        lab.approve(self.folder, "test-fixture")
        self.root = patch("app.web.ROOT", self.folder / "approved")
        self.root.start()
        self.addCleanup(self.root.stop)
        self.initialize = patch("app.web.storage.initialize")
        self.initialize.start()
        self.addCleanup(self.initialize.stop)
        self.overview = patch("app.web.storage.overview", return_value={
            "totals": {"total": 0, "findings": 0, "blocked": 0},
            "runs": [], "audit": [], "campaigns": [], "approvals": [],
        })
        self.overview.start()
        self.addCleanup(self.overview.stop)
        self.client = TestClient(app)
        self.client.__enter__()
        self.addCleanup(lambda: self.client.__exit__(None, None, None))

    def test_dashboard_uses_the_charter_url(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(TARGET, response.text)
        self.assertIn("zero.webappsecurity.com", response.text)
        self.assertNotIn("http-equiv=\"refresh\"", response.text)
        self.assertIn("type=\"text\"", response.text)
        self.assertIn("form-action 'self'", response.headers["content-security-policy"])

    def test_out_of_scope_capture_is_refused(self):
        with patch("app.web.request_through_proxy") as send:
            response = self.client.post("/actions/capture", data={"url": "http://evil.example/", "method": "GET"},
                                        follow_redirects=False)
            send.assert_not_called()
        self.assertEqual(response.status_code, 303)
        self.assertIn("allow", response.headers["location"])

    def test_in_scope_capture_redirects_to_the_run(self):
        class Response:
            headers = {"X-Charter-Run": "11111111-1111-1111-1111-111111111111"}

        with patch("app.web.request_through_proxy", return_value=Response()) as send:
            response = self.client.post("/actions/capture", data={"url": TARGET, "method": "GET"}, follow_redirects=False)
        send.assert_called_once()
        self.assertEqual(response.headers["location"], "/runs/11111111-1111-1111-1111-111111111111")

    def test_autonomous_test_accepts_a_non_local_origin(self):
        with patch("app.web.Llm.from_env", return_value=object()), \
             patch("app.web.storage.running_campaign", return_value=None), \
             patch("app.web.storage.start_campaign", return_value="cid"), \
             patch("app.web.threading.Thread") as thread:
            thread.return_value.start = lambda: None
            response = self.client.post(
                "/actions/campaign",
                data={"url": TARGET, "goal": "Prove access control", "unattended": "1"},
                headers={"origin": "http://203.0.113.5:8000", "host": "testserver"},
                follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertNotIn("local operator", response.text)
        self.assertEqual(response.headers["location"], "/campaigns/cid")

    def test_open_mode_captures_a_url_outside_the_charter(self):
        os.environ["CHARTER_OPEN"] = "1"
        self.addCleanup(os.environ.pop, "CHARTER_OPEN", None)

        class Response:
            headers = {"X-Charter-Run": "22222222-2222-2222-2222-222222222222"}

        with patch("app.web.request_through_proxy", return_value=Response()) as send:
            response = self.client.post("/actions/capture",
                                        data={"url": "http://zero.webappsecurity.com/", "method": "GET"},
                                        follow_redirects=False)
        send.assert_called_once()
        self.assertEqual(response.headers["location"], "/runs/22222222-2222-2222-2222-222222222222")

    def test_campaign_starts_for_the_chosen_url(self):
        with patch("app.web.Llm.from_env", return_value=object()), \
             patch("app.web.storage.running_campaign", return_value=None), \
             patch("app.web.storage.start_campaign", return_value="cid") as started, \
             patch("app.web.threading.Thread") as thread:
            thread.return_value.start = lambda: None
            response = self.client.post("/actions/campaign",
                                        data={"url": TARGET, "goal": "Prove access control", "unattended": "1"},
                                        follow_redirects=False)
        self.assertEqual(response.headers["location"], "/campaigns/cid")
        self.assertEqual(thread.call_args.kwargs["args"][3], TARGET)
        started.assert_called_once()

    def test_campaign_record_omits_the_test_password(self):
        with patch("app.web.Llm.from_env", return_value=object()), \
             patch("app.web.storage.running_campaign", return_value=None), \
             patch("app.web.storage.start_campaign", return_value="cid") as started, \
             patch("app.web.threading.Thread") as thread:
            thread.return_value.start = lambda: None
            self.client.post("/actions/campaign", data={
                "url": TARGET, "goal": "Prove access control", "unattended": "1",
                "auth_user": "ada@example.test", "auth_password": "Lab-secret-99",
            }, follow_redirects=False)
        self.assertNotIn("Lab-secret-99", json.dumps(started.call_args.args[1]))
        self.assertEqual(thread.call_args.kwargs["args"][6]["password"], "Lab-secret-99")
        self.assertTrue(started.call_args.args[1]["authenticated"])

    def test_campaign_starts_when_no_model_is_configured(self):
        from app.llm import LlmError
        with patch("app.web.Llm.from_env", side_effect=LlmError("Set CHARTER_LLM_BASE_URL and CHARTER_LLM_MODEL")), \
             patch("app.web.storage.running_campaign", return_value=None), \
             patch("app.web.storage.start_campaign", return_value="cid"), \
             patch("app.web.threading.Thread") as thread:
            thread.return_value.start = lambda: None
            response = self.client.post("/actions/campaign",
                                        data={"url": TARGET, "goal": "Prove access control", "unattended": "1",
                                              "auth_user2": "bob@example.test", "auth_password2": "Lab-secret-22"},
                                        follow_redirects=False)
        self.assertEqual(response.headers["location"], "/campaigns/cid")
        self.assertIsNone(thread.call_args.kwargs["args"][1])
        self.assertEqual(thread.call_args.kwargs["args"][6]["second"]["password"], "Lab-secret-22")


if __name__ == "__main__":
    unittest.main()
