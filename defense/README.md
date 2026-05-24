# Defense Module

This folder contains defensive building blocks for mitigating credential stuffing.

## Contents

- `account_lock.py`: account lockout after repeated failures.
- `captcha.py`: challenge issuance/verification after failure thresholds.
- `adaptive_auth.py`: lightweight risk scoring from IP and User-Agent patterns.
- `mitigation_report.md`: written mitigation strategy and observations.

## Current Status

These modules are wired into `target-app/app.py`:

- Account lock state checks happen before credential verification.
- CAPTCHA challenge is required after repeated failures.
- Adaptive risk scoring can block high-risk patterns.

Configuration is controlled through environment variables in `target-app`:

- `DEFENSE_ENABLED` (default `1`)
- `ADAPTIVE_BLOCK_SCORE` (default `80`)
