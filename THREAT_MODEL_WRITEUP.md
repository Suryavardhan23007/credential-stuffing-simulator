# Threat Model Write-up

## 1. Scope

This threat model covers a locally hosted Flask login application under credential stuffing attack simulation.

MITRE ATT&CK mapping:
- `T1110.004` Credential Stuffing

## 2. Assets

- User accounts in `target-app/users.db`
- Authentication endpoint `POST /login`
- Session/authentication outcomes
- Monitoring logs and dashboard telemetry

## 3. Adversary Model

Attacker capabilities in this project:
- Can automate high-volume login attempts asynchronously
- Can rotate apparent source IP via proxy-list style header rotation
- Can rotate User-Agent values
- Can vary request timing and concurrency
- Can run combination attacks across username/password sets

Attacker limitations in this simulator:
- No real botnet/proxy infrastructure
- No exploitation beyond authentication abuse
- No destructive post-auth actions

## 4. Entry Points and Trust Boundaries

Primary entry point:
- `POST /login`

Key trust boundary:
- Client-controlled headers (`X-Forwarded-For`) are accepted for lab simulation.
- In real production, these must be trusted only from known reverse proxies.

## 5. Attack Path (Credential Stuffing)

1. Build username/password candidate space.
2. Send automated async requests to `/login`.
3. Rotate apparent source IP per request.
4. Rotate User-Agent values to reduce fingerprint consistency.
5. Jitter timing to avoid naive burst-only detection.
6. Detect success via response content.
7. Produce report of discovered valid credentials.

## 6. Weaknesses Demonstrated

- Naive per-IP rate limiting can be bypassed by source rotation.
- Weak or static controls fail against distributed low-friction attempts.
- Credential reuse in user population leads to account compromise risk.

## 7. Defensive Controls Modeled

- Account lockout (`defense/account_lock.py`)
- CAPTCHA challenge (`defense/captcha.py`)
- Adaptive risk checks (`defense/adaptive_auth.py`)
- Monitoring and event reason logging (`target-app/app.py`)

These controls are toggled for comparison:
- `DEFENSE_ENABLED=0` attack-focused baseline
- `DEFENSE_ENABLED=1` defense demonstration mode

## 8. Residual Risk and Limitations

- Header-based IP simulation is intentionally simplified.
- No MFA, anomaly scoring backend, or cross-service telemetry pipeline.
- In-memory/stateful controls are not horizontally distributed.
- No production-grade anti-automation stack (WAF/bot detection/device fingerprinting).

## 9. Recommended Production Mitigations

1. Multi-signal throttling (IP + account + device + ASN + behavior).
2. Progressive challenges (CAPTCHA/step-up auth) on risk triggers.
3. Strong account lockout + user notification workflow.
4. Enforce MFA for sensitive accounts.
5. Detect leaked/weak credentials and require resets.
6. Centralized telemetry and alerting for distributed stuffing patterns.

## 10. Validation Evidence

Evaluation evidence should include:
- attack logs showing full combination attempts,
- detected successful credentials,
- Burp traffic confirming IP/UA rotation and request patterns,
- dashboard/log evidence for block reasons in defense mode.
