FROM python:3.12-slim

WORKDIR /app

COPY target-app/requirements.txt /app/target-app/requirements.txt
RUN pip install --no-cache-dir -r /app/target-app/requirements.txt

COPY target-app /app/target-app
COPY defense /app/defense
RUN rm -rf /app/target-app/users.db \
    && mkdir -p /app/target-app/logs \
    && touch /app/target-app/logs/attack_logs.txt

EXPOSE 5000

WORKDIR /app/target-app

CMD ["flask", "--app", "app", "run", "--host", "0.0.0.0", "--port", "5000"]
