import os
import unittest

from app.governor import BudgetExhausted, Governor


class GovernorTests(unittest.TestCase):
    def test_interval_uses_the_injected_clock(self):
        clock = {"now": 0.0}
        slept = []
        governor = Governor(2, 5, 100, 1.5, monotonic_fn=lambda: clock["now"], sleep_fn=slept.append)
        governor.before_request()
        clock["now"] = 1.0
        governor.before_request()
        self.assertEqual(slept, [0.5])
        governor.before_turn()
        governor.before_turn()
        with self.assertRaises(BudgetExhausted):
            governor.before_turn()

    def test_from_env(self):
        previous = {name: os.environ.get(name) for name in
                    ("CHARTER_MAX_TURNS", "CHARTER_MAX_REQUESTS", "CHARTER_TOKEN_BUDGET", "CHARTER_MIN_INTERVAL")}
        os.environ["CHARTER_MAX_TURNS"] = "3"
        os.environ["CHARTER_MAX_REQUESTS"] = "4"
        os.environ["CHARTER_TOKEN_BUDGET"] = "5"
        os.environ["CHARTER_MIN_INTERVAL"] = "0"
        try:
            governor = Governor.from_env()
        finally:
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
        self.assertEqual((governor.max_turns, governor.max_requests, governor.max_tokens, governor.min_interval), (3, 4, 5, 0))


if __name__ == "__main__":
    unittest.main()
