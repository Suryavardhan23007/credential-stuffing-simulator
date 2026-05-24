from __future__ import annotations

import secrets


class CaptchaChallenge:
    def __init__(self, failures_before_challenge: int = 3) -> None:
        self.failures_before_challenge = failures_before_challenge
        self._tokens: dict[str, str] = {}

    def required(self, username: str, failed_attempts: int) -> bool:
        return failed_attempts >= self.failures_before_challenge

    def issue(self, username: str) -> str:
        token = secrets.token_hex(3)
        self._tokens[username] = token
        return token

    def verify(self, username: str, submitted_token: str | None) -> bool:
        expected = self._tokens.get(username)
        if not expected:
            return True

        if submitted_token and secrets.compare_digest(expected, submitted_token):
            self._tokens.pop(username, None)
            return True

        return False
