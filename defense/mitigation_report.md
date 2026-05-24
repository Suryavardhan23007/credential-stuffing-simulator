# Credential Stuffing Mitigation Report

## Scope

This project demonstrates MITRE ATT&CK T1110.004, Credential Stuffing, against a locally hosted Flask login target. The offensive simulation uses only lab-safe controls such as simulated source IPs through `X-Forwarded-For`, User-Agent rotation, and randomized delays. No real proxy infrastructure or external targets are used.

## Weakness Demonstrated

The vulnerable mode protects `/login` with a naive per-IP failure counter. This control blocks repeated attempts from one source, but it fails when requests appear to come from many different source IPs. Attackers commonly exploit this weakness by distributing attempts across infrastructure and by changing request metadata.

Observed weaknesses:

- Rate limiting is keyed only by source IP.
- The application trusts `X-Forwarded-For` without a trusted reverse proxy boundary.
- There is no account-level protection.
- There is no step-up authentication for unusual login patterns.
- Login telemetry is not used to detect distributed attacks.

## Implemented Defensive Controls

### Account Lockout

The strong mode tracks failed attempts per username. After repeated failures, the account is temporarily locked. This blocks distributed attempts against the same account even when the apparent source IP changes.

Implementation: `defense/account_lock.py`

### CAPTCHA Simulation

After a configurable number of failed attempts, the application requires a CAPTCHA token. In this lab, the token is displayed directly so the mechanism is easy to demo without depending on a third-party CAPTCHA provider.

Implementation: `defense/captcha.py`

### Adaptive Authentication

The application calculates a simple risk score using source IP diversity and User-Agent diversity for the same account. High-risk attempts receive a step-up authentication response instead of a normal login decision.

Implementation: `defense/adaptive_auth.py`

### Monitoring

The app writes structured authentication logs to `logs/auth.log`, including username, source IP, User-Agent, result, risk score, and blocking reason. These logs support the demo dashboard or manual review.

## Recommended Production Mitigations

1. Rate limit by account, source IP, device, ASN, and session signals rather than IP alone.
2. Do not trust `X-Forwarded-For` from the public internet. Only honor it from known reverse proxies or load balancers.
3. Add progressive friction, such as CAPTCHA, after suspicious failed attempts.
4. Use adaptive authentication with step-up MFA for unusual source, device, velocity, or geography.
5. Implement breached-password detection and require password resets for exposed credentials.
6. Block username enumeration by returning consistent error messages and response timing.
7. Add monitoring rules for many usernames from one source, many sources against one username, high failed-login velocity, repeated password reuse, and unusual User-Agent churn.
8. Prefer phishing-resistant MFA for sensitive accounts.
9. Maintain an allowlist of trusted proxy headers and preserve original client metadata securely.
10. Send user notifications for suspicious login activity and successful logins from new devices.

## Demo Evidence To Capture

- Weak mode: one source IP reaches HTTP 429.
- Weak mode bypass: rotating simulated IPs avoids the IP-only counter.
- Strong mode: repeated attempts against one username trigger CAPTCHA and then account lockout.
- Strong mode: high IP/User-Agent diversity triggers step-up authentication.
- Logs: `logs/auth.log` shows failed attempts, blocked attempts, and defensive reasons.

## Limitations

This is an educational simulator. Real production systems need hardened storage, distributed rate-limiting state, trusted proxy configuration, centralized telemetry, alerting, and secure CAPTCHA/MFA integrations.
