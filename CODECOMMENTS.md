# Code Comments Guide

This file summarizes where important inline code comments are present and why they were added.

## Purpose

The project includes focused comments only at logic points where evaluator clarity matters:
- attack flow behavior,
- evasion mechanics,
- adaptive defense decisions,
- runtime state reset and imports.

## Commented Areas

### 1. Attack Engine

File: `attacker/attack.py`

- Repo import bootstrap:
  - explains why `sys.path` is adjusted for direct script execution.
- Request pacing:
  - explains delay jitter usage for evasive timing simulation.
- Burp integration:
  - explains optional upstream proxy routing for traffic capture.
- Combination ordering:
  - explains password-major ordering for realistic stuffing progression.

### 2. Evasion Module

File: `evasion/ip_rotation.py`

- Proxy list rotation:
  - explains round-robin behavior for deterministic IP rotation in demonstrations.
- Fallback random generation:
  - already documented with unseen-IP preference for bypass clarity.

### 3. Target App

File: `target-app/app.py`

- Shared import path:
  - explains how shared defense modules are importable when app runs directly.
- Defense pipeline:
  - comments on adaptive IP throttle check order and account-level protection.
- Dynamic limit logic:
  - explains why per-IP limit shrinks under suspicious diversity.

### 4. Defense Logic

File: `defense/adaptive_auth.py`

- Risk signal tracking:
  - explains account-level diversity tracking and why it indicates stuffing risk.

## Notes for Evaluators

- Comments are intentionally concise to keep production readability.
- Detailed conceptual explanations are in:
  - `THREAT_MODEL_WRITEUP.md`
  - `SETUP_DOCUMENTATION.md`
  - `defense/mitigation_report.md`
