"""Turn, token, and request budgets, plus the pause between outbound requests."""
import os
from time import monotonic, sleep


class BudgetExhausted(Exception):
    pass


def _int(name, default):
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default
    return value if value >= 0 else default


def _float(name, default):
    try:
        value = float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default
    return value if value >= 0 else default


class Governor:
    def __init__(self, max_turns, max_requests, max_tokens, min_interval, *, monotonic_fn=None, sleep_fn=None):
        self.max_turns = max_turns
        self.max_requests = max_requests
        self.max_tokens = max_tokens
        self.min_interval = min_interval
        self.turns = 0
        self.requests = 0
        self.tokens = 0
        self._next = 0.0
        self._monotonic = monotonic_fn or monotonic
        self._sleep = sleep_fn or sleep

    @classmethod
    def from_env(cls):
        return cls(_int("CHARTER_MAX_TURNS", 40), _int("CHARTER_MAX_REQUESTS", 400),
                   _int("CHARTER_TOKEN_BUDGET", 400000), _float("CHARTER_MIN_INTERVAL", 1))

    def snapshot(self):
        return {"turns_remaining": max(0, self.max_turns - self.turns),
                "requests_remaining": max(0, self.max_requests - self.requests),
                "tokens_remaining": max(0, self.max_tokens - self.tokens)}

    def before_turn(self):
        if self.turns >= self.max_turns:
            raise BudgetExhausted("turn budget exhausted")
        self.turns += 1

    def before_request(self):
        if self.requests >= self.max_requests:
            raise BudgetExhausted("request budget exhausted")
        self._wait()
        self.requests += 1
        self._next = self._monotonic() + self.min_interval

    def pause(self):
        """Wait out a proxy rate-limit without counting another request."""
        if self.min_interval:
            self._sleep(self.min_interval)

    def add_tokens(self, count):
        self.tokens += max(0, int(count))
        if self.tokens > self.max_tokens:
            raise BudgetExhausted("token budget exhausted")

    def _wait(self):
        from .scope_gate import restrictions_open
        if restrictions_open():
            return
        delay = self._next - self._monotonic()
        if delay > 0:
            self._sleep(delay)
