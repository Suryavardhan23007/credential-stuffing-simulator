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

### 1. Project Structure Setup
Created attacker module folder and required files.

---

### 2. Dependency Planning
Selected required libraries for asynchronous HTTP requests and terminal logging.

Current dependencies:

```text
aiohttp
colorama
```

---

### 3. Credentials Dataset Preparation
Prepared credential dataset containing:
- valid credentials,
- invalid credentials,
- realistic credential stuffing simulation data.

Current dataset:
- Total credentials: 50
- Valid credentials: 6
- Invalid credentials: 44

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

# Planned Features

The attack engine will implement:

- asynchronous HTTP requests
- concurrent login attempts
- login success detection
- failed login detection
- attack reporting
- terminal logging

---

# Technologies

| Component | Technology |
|---|---|
| Language | Python |
| HTTP Client | aiohttp |
| Async Framework | asyncio |
| Terminal Output | colorama |

---

# Planned Workflow

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

# Next Development Steps

Planned implementation order:

1. Write asynchronous attack engine
2. Add login request handling
3. Implement success detection
4. Generate attack reports
5. Perform integration testing

---

# Author

Person 1 — Attack Engine Developer