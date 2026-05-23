# Credential Stuffing Attack Simulator & Rate-Limit Bypass Framework

## Overview

This project is an educational cybersecurity simulation framework designed to demonstrate how weak rate-limiting protections on login systems can be bypassed using credential stuffing techniques.

The project simulates:
- Credential stuffing attacks
- User-Agent rotation
- Fake IP rotation
- Request timing randomization
- Detection of successful logins
- Defensive countermeasures

The framework operates entirely in a local isolated environment using Docker containers and intentionally vulnerable applications.

---

# DISCLAIMER

This project is strictly for:
- educational purposes,
- cybersecurity awareness,
- and ethical security research.

This framework:
- MUST only target locally hosted vulnerable applications,
- MUST NOT be used against public systems,
- MUST NOT use real leaked credentials,
- MUST NOT perform unauthorized testing.

---

# Problem Statement

A web application's login endpoint is protected by naive rate limiting, but the protection is insufficient.

The objective is to build an automated credential stuffing framework that:
1. Rotates through multiple simulated IP addresses
2. Varies User-Agent headers
3. Randomizes request timing
4. Detects successful logins
5. Generates attack reports
6. Demonstrates defensive mitigations

---

# Architecture

```text
                +----------------------+
                | credentials.txt      |
                +----------------------+
                           |
                           v
                +----------------------+
                | Attack Engine        |
                | aiohttp async        |
                +----------------------+
                           |
           ---------------------------------------
           |                |                    |
           v                v                    v
    User-Agent       Fake IP Rotation      Random Delays
      Rotation         (X-Forwarded-For)
                           |
                           v
                +----------------------+
                | Flask Login Target   |
                | Weak Rate Limiter    |
                +----------------------+
                           |
                           v
                +----------------------+
                | Monitoring & Logs    |
                +----------------------+
                           |
                           v
                +----------------------+
                | Defense Layer        |
                | CAPTCHA / Lockout    |
                +----------------------+
                           |
                           v
                +----------------------+
                | Reports & Dashboard  |
                +----------------------+
```

---

# Tech Stack

| Component | Technology |
|---|---|
| Attack Engine | Python |
| Async Requests | aiohttp |
| Vulnerable App | Flask |
| Database | SQLite |
| Evasion | fake-useragent |
| Monitoring | Flask Logging |
| Containers | Docker |
| Orchestration | Docker Compose |
| Collaboration | GitHub |
| Dashboard (Optional) | Streamlit |

---

# Project Structure

```text
credential-stuffing-simulator/
│
├── attacker/
│   ├── attack.py
│   ├── credentials.txt
│   ├── requirements.txt
│   └── Dockerfile
│
├── evasion/
│   ├── user_agents.py
│   ├── ip_rotation.py
│   ├── delay_manager.py
│
├── target-app/
│   ├── app.py
│   ├── templates/
│   ├── database.db
│   ├── requirements.txt
│   └── Dockerfile
│
├── defense/
│   ├── captcha.py
│   ├── account_lock.py
│   ├── mitigation_report.md
│
├── logs/
│
├── dashboard/
│
├── docker-compose.yml
│
├── README.md
│
└── PROJECT_CONTEXT.md
```

---

# Team Responsibilities

## Person 1 — Attack Engine
Responsibilities:
- Build async credential stuffing engine
- Implement automated login requests
- Detect successful logins
- Generate attack reports

Technologies:
- Python
- aiohttp
- asyncio

---

## Person 2 — Evasion + Docker + Networking
Responsibilities:
- Implement User-Agent rotation
- Simulate IP rotation
- Randomize request timing
- Configure Docker networking
- Manage container communication

Technologies:
- fake-useragent
- Docker
- Docker Compose

---

## Person 3 — Target Application + Monitoring
Responsibilities:
- Build vulnerable Flask login application
- Implement weak rate limiting
- Configure monitoring and logging
- Manage SQLite user database

Technologies:
- Flask
- SQLite
- Flask-Limiter

---

## Person 4 — Defense + Dashboard + Presentation
Responsibilities:
- Implement CAPTCHA simulation
- Implement account lockout
- Build mitigation report
- Prepare final presentation/demo

Technologies:
- Flask
- Dashboard/UI tools
- Documentation

---

# Features

## Offensive Features
- Credential stuffing automation
- Async concurrent requests
- Fake IP rotation simulation
- User-Agent rotation
- Request timing randomization
- Login success detection

---

## Defensive Features
- CAPTCHA simulation
- Account lockout
- Adaptive authentication
- Monitoring and logging
- Stronger rate limiting

---

# Docker Usage

## Build Containers

```bash
docker-compose build
```

## Start Services

```bash
docker-compose up
```

## Stop Services

```bash
docker-compose down
```

---

# Running The Project

## Step 1 — Start Target Application

```bash
cd target-app
python app.py
```

---

## Step 2 — Run Attack Engine

```bash
cd attacker
python attack.py
```

---

## Step 3 — Monitor Logs

View:
- failed login attempts
- successful logins
- suspicious IPs
- request patterns

---

# Demo Flow

## Phase 1 — Vulnerable System
Show weak rate limiting.

---

## Phase 2 — Attack Blocked
Demonstrate normal attack triggering:
- HTTP 429
- Too Many Requests

---

## Phase 3 — Evasion Enabled
Enable:
- fake IP rotation
- User-Agent rotation
- random delays

Demonstrate bypass.

---

## Phase 4 — Defense Enabled
Enable:
- CAPTCHA
- account lockout
- adaptive authentication

Demonstrate attack prevention.

---

# Important Notes

This project intentionally simplifies:
- IP rotation
- proxy infrastructure
- distributed attacks

to maintain:
- safety,
- legality,
- educational value,
- and hackathon feasibility.

Real-world offensive infrastructure is NOT implemented.

---

# MITRE ATT&CK Mapping

Technique:
- T1110.004 — Credential Stuffing

Reference:
https://attack.mitre.org/techniques/T1110/004/

---

# Future Improvements

Possible future enhancements:
- Real dashboard visualization
- ML-based anomaly detection
- Device fingerprinting
- Distributed attack simulation
- SIEM integration
- Kubernetes deployment

---

# Contributors

- Person 1 — Attack Engine
- Person 2 — Evasion + Docker
- Person 3 — Target App + Monitoring
- Person 4 — Defense + Presentation

---

# License

This project is intended solely for:
- academic use,
- cybersecurity education,
- and authorized security research.