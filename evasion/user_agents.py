from __future__ import annotations

import random

from fake_useragent import UserAgent


DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_5) AppleWebKit/605.1.15 Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Version/17.4 Mobile/15E148 Safari/604.1",
]


class UserAgentRotator:
    """Best-effort user-agent provider with stable local fallback."""

    def __init__(self) -> None:
        try:
            self._provider = UserAgent()
        except Exception:
            self._provider = None

    def get_random_user_agent(self) -> str:
        if self._provider is not None:
            try:
                return self._provider.random
            except Exception:
                pass
        return random.choice(DEFAULT_USER_AGENTS)
