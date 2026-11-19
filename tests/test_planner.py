import json
from pathlib import Path
import unittest

from app.planner import SYSTEM_PROMPT, parse_plan


class PlannerTests(unittest.TestCase):
    def test_fenced_json_and_invalid_tasks(self):
        text = "```json\n" + json.dumps({
            "summary": "next",
            "tasks": [
                {"worker": "http", "intent": "bad method", "method": "TRACE", "url": "http://juice-shop:3000/"},
                {"worker": "http", "intent": "bad header", "method": "GET", "url": "http://juice-shop:3000/",
                 "headers": {"X-Charter-Campaign": "no"}},
                {"worker": "http", "intent": "ok", "method": "GET", "url": "http://juice-shop:3000/",
                 "headers": {"Accept": "text/html"}},
            ],
        }) + "\n```"
        plan = parse_plan(text)
        self.assertEqual(len(plan.tasks), 1)
        self.assertEqual(plan.tasks[0]["method"], "GET")
        self.assertEqual(plan.tasks[0]["headers"], {"accept": "text/html"})
        self.assertIn("Skipped", plan.summary)

    def test_sqlmap_extra_arguments_are_dropped(self):
        plan = parse_plan(json.dumps({
            "summary": "inject",
            "tasks": [{"worker": "sqlmap", "intent": "test the search",
                       "url": "http://zero.webappsecurity.com/search.html?q=1", "args": ["--os-shell"]}],
        }))
        self.assertNotIn("args", plan.tasks[0])
        self.assertEqual(plan.tasks[0]["worker"], "sqlmap")

    def test_only_invalid_tasks_reject_the_plan(self):
        with self.assertRaises(ValueError):
            parse_plan(json.dumps({"tasks": [{"worker": "http", "intent": "bad", "method": "TRACE",
                                              "url": "http://juice-shop:3000/"}]}))

    def test_coverage_check_and_task_allowance(self):
        tasks = [{"worker": "coverage", "check": "xss-reflected", "intent": f"step {index}"} for index in range(9)]
        tasks.append({"worker": "coverage", "check": "not-a-check", "intent": "invalid"})
        plan = parse_plan(json.dumps({"summary": "chain", "tasks": tasks}))
        self.assertEqual(len(plan.tasks), 8)
        self.assertTrue(all(item["worker"] == "coverage" and item["check"] == "xss-reflected" for item in plan.tasks))
        self.assertIn("Kept 8", plan.summary)
        self.assertIn("coverage", SYSTEM_PROMPT)
        self.assertIn("xss-stored", SYSTEM_PROMPT)
        self.assertIn("enforced in code", SYSTEM_PROMPT)

    def test_prompt_does_not_contain_the_auth_marker(self):
        self.assertNotIn("Authenticated.", SYSTEM_PROMPT)
        self.assertIn("Ignore", SYSTEM_PROMPT)
        source = Path("app/llm.py").read_text(encoding="utf-8")
        self.assertNotIn("sk-", source)


if __name__ == "__main__":
    unittest.main()
