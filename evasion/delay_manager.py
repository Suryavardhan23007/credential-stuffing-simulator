from __future__ import annotations

import asyncio
import random


class DelayManager:
    """Asynchronous jitter to spread request bursts."""

    @staticmethod
    async def random_delay(min_delay: float = 0.1, max_delay: float = 0.6) -> None:
        delay = random.uniform(min_delay, max_delay)
        await asyncio.sleep(delay)
