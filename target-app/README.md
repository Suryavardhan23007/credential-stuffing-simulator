# Vulnerable Login Lab

This Flask application is intentionally vulnerable and is only for controlled educational cybersecurity testing on trusted lab systems.

## Architecture

```text
Flask
  |
  v
SQLite users.db
  |
  v
users table
```

The login flow now uses SQLite instead of `users.json`. Credentials are checked with a parameterized query:

```sql
SELECT id, username
FROM users
WHERE username = ? AND password = ?;
```

## Database Initialization

On startup, `app.py` automatically creates `users.db` and the `users` table if they do not exist. It then inserts the demo accounts with `INSERT OR IGNORE`, so restarting the app does not duplicate users.

Schema:

```sql
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);
```

Demo credentials:

```text
admin  : admin123
john   : password123
alice  : alice2024
mike   : mikepass
guest  : guest123
surya  : surya@123
```

## What It Demonstrates

- Credential stuffing against a weak database-backed login form
- Per-IP rate limiting at 10 requests/minute
- Fixed-window rate limiting that can be bypassed with request timing
- User-Agent tracking for browser fingerprint randomization demos
- IP tracking and attack visibility from a dashboard
- Adaptive defenses: account lockout, CAPTCHA challenge, adaptive risk scoring, burst cooldown

## Install Locally

```powershell
cd project
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Run Locally

```powershell
python app.py
```

Optional defense toggles:

```powershell
$env:DEFENSE_ENABLED=1
$env:ADAPTIVE_BLOCK_SCORE=80
python app.py
```

Open on the host laptop:

```text
http://localhost:5000
```

Dashboard:

```text
http://localhost:5000/dashboard
```

Open from another laptop on the same Wi-Fi:

```text
http://<host-laptop-lan-ip>:5000
```

Example:

```text
http://192.168.1.25:5000
```

## Docker

```powershell
docker compose up --build
```

From the project root, you can run integrated attacker + target simulation:

```powershell
docker compose up --build
```

The compose file publishes port `5000` on all host interfaces and persists logs:

```text
./logs -> /app/logs
```

The SQLite database is created at `/app/users.db` inside the container. The Docker build ignores local `users.db` artifacts so an accidental host directory cannot be copied over the database path. Avoid binding a single host file to `/app/users.db`; if the host file does not exist, Docker can create an incompatible directory and SQLite may fail to open it.

Then open:

```text
http://localhost:5000
```

From another laptop on the same Wi-Fi, open:

```text
http://<host-laptop-lan-ip>:5000
```

## Example Login Request

```powershell
curl -i -X POST http://localhost:5000/login -d "username=admin&password=admin123" -A "TrainingBrowser/1.0"
```

## Example Failed Simulation Request

```powershell
curl -i -X POST http://localhost:5000/login -d "username=admin&password=wrong-password" -A "Rotated-UA-Demo/42"
```

## Why The Rate Limits Are Weak

The per-IP limiter allows 5 POST requests per minute from each source IP. This is weak because it only keys on `request.remote_addr`, so traffic distributed across different proxies appears to come from different IP addresses.

The fixed-window limiter allows 10 login attempts every 60 seconds. This is weak because the counter resets on a rigid boundary, so attackers can slow down or time requests around the reset instead of being controlled by an adaptive or sliding-window defense.

For lab demonstration purposes, this app also trusts `X-Forwarded-For` headers to simulate proxy rotation from a single machine. Do not use this trust model in production unless requests come through a trusted reverse proxy.

## Important Safety Boundary

Do not target real websites. Do not run credential stuffing outside your controlled lab network. This project exists only so defenders can observe weak authentication controls in a safe environment.
