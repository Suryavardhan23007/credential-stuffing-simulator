from __future__ import annotations

import random
from pathlib import Path


class IPRotator:
    """Rotate IPs from a proxy list, with randomized fallback."""

    def __init__(self, proxy_list_path: str | None = None) -> None:
        self._recent: set[str] = set()
        self._proxy_ips: list[str] = []
        self._proxy_index = 0

        if proxy_list_path:
            self._proxy_ips = self._load_proxy_list(proxy_list_path)
            random.shuffle(self._proxy_ips)

    @staticmethod
    def _load_proxy_list(proxy_list_path: str) -> list[str]:
        path = Path(proxy_list_path)
        if not path.exists():
            return []
        ips: list[str] = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                item = line.strip()
                if not item or item.startswith("#"):
                    continue
                # Accept "ip" or "ip:port"; for header spoofing use only ip.
                ip = item.split(":", 1)[0].strip()
                if ip:
                    ips.append(ip)
        return ips

    def generate_fake_ip(self) -> str:
        if self._proxy_ips:
            # Round-robin through configured proxy list for deterministic rotation in demos.
            ip = self._proxy_ips[self._proxy_index]
            self._proxy_index = (self._proxy_index + 1) % len(self._proxy_ips)
            return ip

        # Keep rotating to unseen IPs first for clearer rate-limit bypass demonstrations.
        for _ in range(40):
            candidate = ".".join(str(random.randint(1, 254)) for _ in range(4))
            if candidate not in self._recent:
                self._recent.add(candidate)
                if len(self._recent) > 4096:
                    self._recent.clear()
                return candidate
        return ".".join(str(random.randint(1, 254)) for _ in range(4))
