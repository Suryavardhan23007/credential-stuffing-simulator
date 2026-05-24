FROM python:3.12-slim

WORKDIR /app

COPY attacker/requirements.txt /app/attacker/requirements.txt
COPY evasion/requirements.txt /app/evasion/requirements.txt
RUN pip install --no-cache-dir -r /app/attacker/requirements.txt -r /app/evasion/requirements.txt

COPY attacker /app/attacker
COPY evasion /app/evasion

WORKDIR /app/attacker

CMD ["python", "attack.py", "--mode", "combo", "--url", "http://vulnerable-login:5000/login", "--concurrency", "12", "--min-delay", "0.05", "--max-delay", "0.20", "--max-combinations", "900"]
