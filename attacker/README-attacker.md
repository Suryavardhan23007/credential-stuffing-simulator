# Attack Engine Module

## Overview

This module is responsible for the credential stuffing attack simulation component of the project.

The attack engine:
- reads username/password combinations from a credential file,
- sends asynchronous login requests,
- detects successful logins,
- and generates attack reports.

This module is designed strictly for:
- educational purposes,
- cybersecurity awareness,
- and authorized local testing.

---

# Responsibilities

The attack engine performs:

1. Credential loading
2. Automated login attempts
3. Asynchronous request handling
4. Success/failure detection
5. Attack reporting

---

# Folder Structure

```text
attacker/
│
├── attack.py
├── credentials.txt
├── requirements.txt
└── README-attacker.md
```

---

# Current Progress

## Completed

### 1. Async Attack Engine Implemented
`attack.py` now includes:
- async concurrent login attempts (`aiohttp` + `asyncio`)
- configurable concurrency, timeout, and delay range
- User-Agent rotation and spoofed IP rotation (`X-Forwarded-For`, `X-Real-IP`)
- case-insensitive success pattern matching
- per-attempt latency and status tracking

---

### 2. Reporting Implemented
After each run, the engine:
- prints live terminal output for each attempt
- prints final attack summary
- saves structured JSON report to `attacker/reports/`

---

### 3. Credentials Dataset Prepared
Prepared credential dataset containing:
- valid credentials
- invalid credentials
- realistic credential stuffing simulation data

Current dataset:
- Total credentials: 56
- Valid credentials: 6
- Invalid credentials: 50

---

# Valid Credentials

The following credentials are intended to exist in the vulnerable target application database:

```text
admin:admin123
john:password123
alice:alice2024
mike:mikepass
guest:guest123
surya:surya@123
```

These credentials must exactly match the Flask application's user database for successful login detection.

---

# Credential File Format

The credential file uses the following format:

```text
username:password
```

Example:

```text
admin:admin123
```

---

# Implemented Features

- asynchronous HTTP requests
- concurrent login attempts
- login success/failure/error detection
- randomized request delays
- User-Agent rotation
- spoofed IP header rotation
- JSON attack report generation
- terminal progress + summary output

---

# Technologies

| Component | Technology |
|---|---|
| Language | Python |
| HTTP Client | aiohttp |
| Async Framework | asyncio |
| Terminal Output | colorama |

---

# Runtime Workflow

```text
credentials.txt
       ↓
Load credentials
       ↓
Async login requests
       ↓
Success/failure detection
       ↓
Generate report
```

---

# Expected Integration

The vulnerable Flask application is expected to expose:

```text
POST /login
```

Required parameters:

```text
username
password
```

Expected responses:

Successful login:
```text
Login Successful
```

Failed login:
```text
Invalid Credentials
```

---

# Important Notes

This module:
- does NOT target public systems,
- does NOT use real leaked credentials,
- does NOT perform unauthorized testing.

All testing is intended for:
- localhost environments,
- Docker containers,
- and intentionally vulnerable applications only.

---

# How To Run

From project root:

```bash
python3 -m venv .venv
.venv/bin/python3 -m pip install -r attacker/requirements.txt
.venv/bin/python3 attacker/attack.py
```

Useful options:

```bash
.venv/bin/python3 attacker/attack.py \
  --url http://localhost:5000/login \
  --concurrency 10 \
  --timeout 8 \
  --min-delay 0.1 \
  --max-delay 0.6 \
  --success-pattern "Login Successful"
```

---

# Author

Person 1 — Attack Engine Developer
