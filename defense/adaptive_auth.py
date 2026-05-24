from __future__ import annotations

from dataclasses import dataclass, field
from time import time


@dataclass
class SeenUser:
    ips: set[str] = field(default_factory=set)
    user_agents: set[str] = field(default_factory=set)
    first_seen: float = field(default_factory=time)


class AdaptiveAuth:
    def __init__(self, max_ips_per_window: int = 3, max_agents_per_window: int = 4) -> None:
        self.max_ips_per_window = max_ips_per_window
        self.max_agents_per_window = max_agents_per_window
        self._seen: dict[str, SeenUser] = {}

    def risk_score(self, username: str, ip_address: str, user_agent: str) -> tuple[int, list[str]]:
        # Track diversity per target account; unusual diversity implies stuffing behavior.
        record = self._seen.setdefault(username, SeenUser())
        record.ips.add(ip_address)
        record.user_agents.add(user_agent)

        reasons: list[str] = []
        score = 0

        if len(record.ips) > self.max_ips_per_window:
            score += 50
            reasons.append("many_source_ips_for_same_account")

        if len(record.user_agents) > self.max_agents_per_window:
            score += 30
            reasons.append("many_user_agents_for_same_account")

        if ip_address.startswith(("10.10.", "172.16.")):
            score += 20
            reasons.append("known_lab_attack_range")

        return min(score, 100), reasons
