from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass
class AccountState:
    failed_attempts: int = 0
    locked_until: datetime | None = None


class AccountLockout:
    def __init__(self, max_failures: int = 5, lock_minutes: int = 5) -> None:
        self.max_failures = max_failures
        self.lock_duration = timedelta(minutes=lock_minutes)
        self._accounts: dict[str, AccountState] = {}

    def is_locked(self, username: str) -> tuple[bool, datetime | None]:
        state = self._accounts.get(username)
        if not state or not state.locked_until:
            return False, None

        now = datetime.now(timezone.utc)
        if state.locked_until <= now:
            state.failed_attempts = 0
            state.locked_until = None
            return False, None

        return True, state.locked_until

    def record_failure(self, username: str) -> AccountState:
        state = self._accounts.setdefault(username, AccountState())
        state.failed_attempts += 1

        if state.failed_attempts >= self.max_failures:
            state.locked_until = datetime.now(timezone.utc) + self.lock_duration

        return state

    def record_success(self, username: str) -> None:
        self._accounts.pop(username, None)

    def failed_attempts(self, username: str) -> int:
        state = self._accounts.get(username)
        if not state:
            return 0
        return state.failed_attempts
