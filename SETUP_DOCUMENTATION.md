# Setup Documentation

This document explains exactly how to run the project for hackathon evaluation.

## 1. Prerequisites

- Docker Desktop (or Docker Engine + Compose plugin)
- Python 3.11+ (for optional non-Docker run)
- Burp Suite Community (for traffic analysis)

## 2. Project Root

Run all commands from:

```bash
credential-stuffing-simulator/
```

## 3. Recommended Run (Docker)

Start clean:

```bash
docker compose down
```

Build and start:

```bash
docker compose up --build -d
```

Check status:

```bash
docker compose ps -a
```

Expected:
- `vulnerable-login` should be `Up`
- `credential-attacker` should run and complete

App URLs:
- Login: `http://localhost:5050/login`
- Dashboard: `http://localhost:5050/dashboard`

## 4. Read Attack Output

Show attacker logs:

```bash
docker compose logs --no-color --tail=120 attacker
```

Look for:
- all combinations attempted (`[x/900] username:password -> ...`)
- final summary
- discovered valid credentials listed separately

## 5. Check Reports and Logs

- Attack report JSON: `attacker/reports/attack_report_*.json`
- Target logs: `target-app/logs/attack_logs.txt`
- Live monitoring: dashboard URL above

## 6. Defense Mode Toggle

The target app supports an environment toggle:
- `DEFENSE_ENABLED=0` (attack-focused mode, default)
- `DEFENSE_ENABLED=1` (defense demo mode)

Set in `docker-compose.yml` under `vulnerable-login.environment`.

After changing:

```bash
docker compose down
docker compose up --build -d
```

## 7. Optional Local (Non-Docker) Run

Create env and install:

```bash
python3 -m venv .venv
.venv/bin/python3 -m pip install -r attacker/requirements.txt
.venv/bin/python3 -m pip install -r evasion/requirements.txt
.venv/bin/python3 -m pip install -r target-app/requirements.txt
```

Run target:

```bash
env FLASK_RUN_HOST=127.0.0.1 FLASK_RUN_PORT=5000 DEFENSE_ENABLED=0 .venv/bin/python3 target-app/app.py
```

Run attacker from another terminal:

```bash
.venv/bin/python3 attacker/attack.py --mode combo --url http://127.0.0.1:5000/login --max-combinations 900
```

## 8. Burp Proxy Test (Optional)

Route attacker traffic through Burp:

```bash
.venv/bin/python3 attacker/attack.py \
  --mode combo \
  --url http://127.0.0.1:5050/login \
  --max-combinations 900 \
  --http-proxy http://127.0.0.1:8080
```

In Burp HTTP history, verify:
- repeated `POST /login`
- changing `X-Forwarded-For`
- changing `User-Agent`

## 9. Stop Project

```bash
docker compose down
```
