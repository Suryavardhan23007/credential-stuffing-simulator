# Evasion Module

This module provides request-evasion helpers used by the attack engine.

## Contents

- `user_agents.py`: `UserAgentRotator` for randomized User-Agent values.
- `ip_rotation.py`: `IPRotator` for randomized spoofed IPv4 addresses.
- `delay_manager.py`: `DelayManager` for randomized async request delays.
- `requirements.txt`: evasion-specific dependency list.

## Integration

`attacker/attack.py` imports these helpers directly:

- `UserAgentRotator.get_random_user_agent()`
- `IPRotator.generate_fake_ip()`
- `DelayManager.random_delay(min_delay, max_delay)`

## Notes

- Built for authorized local lab simulations only.
- `UserAgentRotator` includes local fallback values if dynamic UA generation fails.
