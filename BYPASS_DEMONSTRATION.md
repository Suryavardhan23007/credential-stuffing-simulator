# Rate-Limit Bypass Demonstration

This document provides explicit proof steps for the deliverable requirement:

> bypass demonstration of at least two common rate-limiting implementations.

## Implementation A: Per-IP Fixed Window (Flask-Limiter)

### What is implemented

- In `target-app/app.py`, `POST /login` is protected by:
  - `@limiter.limit("10 per minute", key_func=client_ip_address, methods=["POST"])`

### Why it is weak

- The limiter key is based on source IP.
- In this lab, the attacker rotates source IP using `X-Forwarded-For`.
- Distributed requests avoid exhausting one IP bucket quickly.

### How to demo bypass

1. Start app and attacker:

```bash
docker compose down
docker compose up --build -d
```

2. Watch attacker output:

```bash
docker compose logs --no-color --tail=140 attacker
```

3. Evidence:
- many requests proceed with status `401`/`200` instead of immediate sustained `429`,
- successful credentials are discovered despite per-IP limit.

4. Optional Burp evidence:
- observe `X-Forwarded-For` changing across requests.

## Implementation B: Naive Global Fixed Window Counter

### What is implemented

- In `target-app/app.py`, global counter logic:
  - `fixed_window_blocked()`
  - `GLOBAL_LOGIN_LIMIT` and `WINDOW_SECONDS`
- Applied in login flow when `DEFENSE_ENABLED=1`.

### Why it is weak

- It is a single global counter that resets every fixed window.
- An attacker can pace/batch traffic around resets to continue attempts.

### How to demo bypass tendency

1. Enable defense and lower global limit for visibility:

```bash
docker compose down
```

Edit `docker-compose.yml` under `vulnerable-login.environment`:
- `DEFENSE_ENABLED=1`
- add `GLOBAL_LOGIN_LIMIT=20`

2. Start stack:

```bash
docker compose up --build -d
```

3. Run attacker with slower pacing (local run) so windows reset during run:

```bash
.venv/bin/python3 attacker/attack.py \
  --mode combo \
  --url http://127.0.0.1:5050/login \
  --concurrency 4 \
  --min-delay 0.4 \
  --max-delay 1.2 \
  --max-combinations 200
```

4. Evidence:
- intermittent blocks occur (`429`),
- attempts resume as window resets,
- demonstrates fixed-window reset weakness under timing-aware traffic.

## Proof Artifacts to Submit

- attacker terminal summary (attempts + discovered valid credentials)
- `attacker/reports/attack_report_*.json`
- `target-app/logs/attack_logs.txt` with block reasons
- Burp HTTP history screenshots showing IP/User-Agent rotation
