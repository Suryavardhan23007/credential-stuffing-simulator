import logging
import os
import sqlite3
import sys
import time
from collections import Counter, defaultdict, deque
from datetime import datetime
from pathlib import Path

from colorama import Fore, Style, init as colorama_init

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    # Allow running target-app/app.py directly while importing shared defense modules.
    sys.path.insert(0, str(REPO_ROOT))

from defense.account_lock import AccountLockout
from defense.adaptive_auth import AdaptiveAuth
from defense.captcha import CaptchaChallenge
from flask import Flask, jsonify, redirect, render_template, request, url_for
from flask_limiter import Limiter


BASE_DIR = Path(__file__).resolve().parent
DATABASE_FILE = BASE_DIR / "users.db"
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "attack_logs.txt"

DEMO_USERS = [
    ("admin", "admin123"),
    ("john", "password123"),
    ("alice", "alice2024"),
    ("mike", "mikepass"),
    ("guest", "guest123"),
    ("surya", "surya@123"),
]

# Intentionally simple fixed-window state for classroom bypass demonstrations.
WINDOW_SECONDS = 60
GLOBAL_LOGIN_LIMIT = int(os.environ.get("GLOBAL_LOGIN_LIMIT", "200"))
global_window_start = time.time()
global_window_count = 0

# In-memory dashboard counters reset when the app restarts.
activity_events = deque(maxlen=100)
metrics = {
    "total_attempts": 0,
    "successful_logins": 0,
    "failed_logins": 0,
    "blocked_requests": 0,
}
ip_counter = Counter()
user_agent_counter = Counter()
timing_samples = deque(maxlen=40)
last_attempt_at = None

DEFENSE_ENABLED = os.environ.get("DEFENSE_ENABLED", "0") == "1"
ADAPTIVE_BLOCK_SCORE = int(os.environ.get("ADAPTIVE_BLOCK_SCORE", "80"))
lockout = AccountLockout(max_failures=5, lock_minutes=5)
captcha = CaptchaChallenge(failures_before_challenge=3)
adaptive_auth = AdaptiveAuth(max_ips_per_window=3, max_agents_per_window=4)

# Adaptive per-IP throttling state.
ip_activity = defaultdict(deque)
ip_blocked_until = {}
IP_BASE_LIMIT_PER_MINUTE = 10
BURST_WINDOW_SECONDS = 10
BURST_THRESHOLD = 6
BURST_BLOCK_SECONDS = 25


def create_app():
    """Create the vulnerable localhost-only Flask application."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "localhost-training-only")

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    LOG_FILE.touch(exist_ok=True)
    colorama_init(autoreset=True)
    configure_logging()
    initialize_database()
    reset_runtime_state()

    limiter = Limiter(key_func=client_ip_address, app=app, default_limits=[], storage_uri="memory://")

    @app.route("/")
    def index():
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit(
        "10 per minute",
        key_func=client_ip_address,
        methods=["POST"],
    )
    def login():
        if request.method == "GET":
            return render_template("login.html", message=None, status=None, captcha_required=False)

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        captcha_token = request.form.get("captcha_token", "").strip()
        ip_address = client_ip_address()
        user_agent = request.headers.get("User-Agent", "unknown")

        if DEFENSE_ENABLED:
            # Dynamic IP throttle layer is evaluated before credential checks.
            adaptive_block_reason = adaptive_ip_block_reason(
                ip_address=ip_address,
                username=username,
                user_agent=user_agent,
            )
            if adaptive_block_reason:
                event = record_attempt(
                    username=username,
                    success=False,
                    blocked=True,
                    reason=adaptive_block_reason,
                )
                return (
                    render_template(
                        "login.html",
                        message="Adaptive IP throttling blocked this request.",
                        status="blocked",
                        event=event,
                        captcha_required=False,
                    ),
                    429,
                )

        if DEFENSE_ENABLED:
            # Account-level controls protect against distributed attacks on one username.
            locked, locked_until = lockout.is_locked(username)
            if locked:
                event = record_attempt(
                    username=username,
                    success=False,
                    blocked=True,
                    reason="account_locked",
                )
                locked_text = locked_until.astimezone().strftime("%H:%M:%S") if locked_until else "later"
                return (
                    render_template(
                        "login.html",
                        message=f"Account temporarily locked until {locked_text}.",
                        status="blocked",
                        event=event,
                        captcha_required=False,
                    ),
                    423,
                )

            risk_score, reasons = adaptive_auth.risk_score(
                username=username,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            if risk_score >= ADAPTIVE_BLOCK_SCORE:
                event = record_attempt(
                    username=username,
                    success=False,
                    blocked=True,
                    reason=f"adaptive_auth_block:{','.join(reasons) or 'high_risk'}",
                )
                return (
                    render_template(
                        "login.html",
                        message="Adaptive defense blocked this request due to high risk.",
                        status="blocked",
                        event=event,
                        captcha_required=False,
                    ),
                    403,
                )

            failed_count = lockout.failed_attempts(username)
            captcha_required = captcha.required(username, failed_count)
            if captcha_required:
                if not captcha_token:
                    challenge = captcha.issue(username)
                    event = record_attempt(
                        username=username,
                        success=False,
                        blocked=True,
                        reason="captcha_challenge_issued",
                    )
                    return (
                        render_template(
                            "login.html",
                            message=f"CAPTCHA required. Submit token: {challenge}",
                            status="blocked",
                            event=event,
                            captcha_required=True,
                        ),
                        401,
                    )

                if not captcha.verify(username, captcha_token):
                    event = record_attempt(
                        username=username,
                        success=False,
                        blocked=True,
                        reason="captcha_verification_failed",
                    )
                    return (
                        render_template(
                            "login.html",
                            message="CAPTCHA verification failed.",
                            status="blocked",
                            event=event,
                            captcha_required=True,
                        ),
                        401,
                    )

        if DEFENSE_ENABLED and fixed_window_blocked():
            event = record_attempt(
                username=username,
                success=False,
                blocked=True,
                reason="global_fixed_window_limit",
            )
            return (
                render_template(
                    "login.html",
                    message="Too many login attempts. Try again soon.",
                    status="blocked",
                    event=event,
                    captcha_required=False,
                ),
                429,
            )

        success = authenticate_user(username, password)
        event = record_attempt(
            username=username,
            success=success,
            blocked=False,
            reason="valid_credentials" if success else "invalid_credentials",
        )

        if success:
            if DEFENSE_ENABLED:
                lockout.record_success(username)
            return render_template(
                "login.html",
                message="Login Successful",
                status="success",
                event=event,
                captcha_required=False,
            )

        if DEFENSE_ENABLED:
            state = lockout.record_failure(username)
            if state.locked_until:
                return (
                    render_template(
                        "login.html",
                        message="Account locked after repeated failures.",
                        status="blocked",
                        event=event,
                        captcha_required=False,
                    ),
                    423,
                )

        return (
            render_template(
                "login.html",
                message="Invalid Credentials",
                status="failure",
                event=event,
                captcha_required=DEFENSE_ENABLED and captcha.required(
                    username, lockout.failed_attempts(username)
                ),
            ),
            401,
        )

    @app.route("/dashboard")
    def dashboard():
        return render_template("dashboard.html", data=dashboard_data())

    @app.route("/api/stats")
    def api_stats():
        return jsonify(dashboard_data())

    @app.errorhandler(429)
    def ratelimit_handler(error):
        event = log_blocked_attempt("per_ip_rate_limit")
        return (
            render_template(
                "login.html",
                message="Per-IP rate limit reached. Rotate IPs and this weak control resets.",
                status="blocked",
                event=event,
            ),
            429,
        )

    return app


def reset_runtime_state():
    """Reset in-memory counters so each fresh app start begins clean."""
    global global_window_count, global_window_start, last_attempt_at
    global lockout, captcha, adaptive_auth

    global_window_start = time.time()
    global_window_count = 0
    last_attempt_at = None

    activity_events.clear()
    timing_samples.clear()
    ip_counter.clear()
    user_agent_counter.clear()
    metrics["total_attempts"] = 0
    metrics["successful_logins"] = 0
    metrics["failed_logins"] = 0
    metrics["blocked_requests"] = 0
    ip_activity.clear()
    ip_blocked_until.clear()

    lockout = AccountLockout(max_failures=5, lock_minutes=5)
    captcha = CaptchaChallenge(failures_before_challenge=3)
    adaptive_auth = AdaptiveAuth(max_ips_per_window=3, max_agents_per_window=4)


def configure_logging():
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(message)s",
    )


def get_database_connection():
    DATABASE_FILE.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    return connection


def client_ip_address():
    xff = request.headers.get("X-Forwarded-For", "").strip()
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def initialize_database():
    """Create the SQLite users table and seed demo accounts when missing."""
    with get_database_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
            """
        )
        connection.executemany(
            """
            INSERT OR IGNORE INTO users (username, password)
            VALUES (?, ?)
            """,
            DEMO_USERS,
        )
        connection.commit()


def authenticate_user(username, password):
    """Check credentials through SQLite using parameterized queries."""
    with get_database_connection() as connection:
        user = connection.execute(
            """
            SELECT id, username
            FROM users
            WHERE username = ? AND password = ?
            """,
            (username, password),
        ).fetchone()
    return user is not None


def fixed_window_blocked():
    """Weak global fixed-window limiter: bursty and easy to evade with timing."""
    global global_window_count, global_window_start

    now = time.time()
    if now - global_window_start >= WINDOW_SECONDS:
        global_window_start = now
        global_window_count = 0

    global_window_count += 1
    return global_window_count > GLOBAL_LOGIN_LIMIT


def adaptive_ip_block_reason(ip_address, username, user_agent):
    """Dynamic throttling that tightens limits based on attacker behavior."""
    now = time.time()
    blocked_until = ip_blocked_until.get(ip_address)
    if blocked_until and now < blocked_until:
        return "adaptive_ip_cooldown"

    history = ip_activity[ip_address]
    history.append(
        {
            "t": now,
            "username": username,
            "user_agent": user_agent,
        }
    )

    while history and now - history[0]["t"] > WINDOW_SECONDS:
        history.popleft()

    recent_window = [entry for entry in history if now - entry["t"] <= BURST_WINDOW_SECONDS]
    unique_users = len({entry["username"] for entry in history if entry["username"]})
    unique_agents = len({entry["user_agent"] for entry in history})

    # Shrink per-IP allowance when one source touches many users/agents quickly.
    dynamic_limit = max(3, IP_BASE_LIMIT_PER_MINUTE - (unique_users // 4) - (unique_agents // 6))
    if len(history) > dynamic_limit:
        return "adaptive_ip_dynamic_limit"

    if len(recent_window) >= BURST_THRESHOLD:
        ip_blocked_until[ip_address] = now + BURST_BLOCK_SECONDS
        return "adaptive_ip_burst_detected"

    return None


def log_blocked_attempt(reason):
    username = request.form.get("username", "").strip() if request.form else ""
    return record_attempt(username=username, success=False, blocked=True, reason=reason)


def record_attempt(username, success, blocked, reason):
    """Record a login event to disk, terminal, and dashboard memory."""
    global last_attempt_at

    now = time.time()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip_address = client_ip_address()
    user_agent = request.headers.get("User-Agent", "unknown")

    seconds_since_last = None
    if last_attempt_at is not None:
        seconds_since_last = round(now - last_attempt_at, 3)
    last_attempt_at = now

    metrics["total_attempts"] += 1
    if blocked:
        metrics["blocked_requests"] += 1
    else:
        if success:
            metrics["successful_logins"] += 1
        else:
            metrics["failed_logins"] += 1

    ip_counter[ip_address] += 1
    user_agent_counter[user_agent] += 1
    if seconds_since_last is not None:
        timing_samples.append(seconds_since_last)

    event = {
        "timestamp": timestamp,
        "ip": ip_address,
        "username": username or "(blank)",
        "user_agent": user_agent,
        "success": success,
        "blocked": blocked,
        "reason": reason,
        "seconds_since_last": seconds_since_last,
    }
    activity_events.appendleft(event)

    log_line = (
        f"timestamp={timestamp} | ip={ip_address} | username={username or '(blank)'} | "
        f"user_agent={user_agent} | success={success} | blocked={blocked} | reason={reason} | "
        f"seconds_since_last={seconds_since_last}"
    )
    logging.info(log_line)
    print_colored_log(log_line, success, blocked)
    return event


def print_colored_log(log_line, success, blocked):
    if blocked:
        color = Fore.YELLOW
    elif success:
        color = Fore.GREEN
    else:
        color = Fore.RED
    print(f"{color}{log_line}{Style.RESET_ALL}")


def dashboard_data():
    active_cooldowns = sum(1 for unblock_at in ip_blocked_until.values() if unblock_at > time.time())
    return {
        "metrics": metrics,
        "top_ips": ip_counter.most_common(10),
        "top_user_agents": user_agent_counter.most_common(10),
        "adaptive": {
            "base_ip_limit_per_minute": IP_BASE_LIMIT_PER_MINUTE,
            "burst_window_seconds": BURST_WINDOW_SECONDS,
            "burst_threshold": BURST_THRESHOLD,
            "burst_block_seconds": BURST_BLOCK_SECONDS,
            "active_ip_cooldowns": active_cooldowns,
        },
        "recent_events": list(activity_events)[:30],
        "timing_samples": list(timing_samples),
        "window": {
            "limit": GLOBAL_LOGIN_LIMIT,
            "seconds": WINDOW_SECONDS,
            "count": global_window_count,
            "resets_in": max(0, round(WINDOW_SECONDS - (time.time() - global_window_start), 1)),
        },
    }


app = create_app()


if __name__ == "__main__":
    # Bind to all interfaces so teammates on the same LAN can access this lab.
    host = os.environ.get("FLASK_RUN_HOST", "0.0.0.0")
    port = int(os.environ.get("FLASK_RUN_PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host=host, port=port, debug=debug)
