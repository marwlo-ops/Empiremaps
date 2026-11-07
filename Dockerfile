FROM python:3.11-slim

ENV TZ=Europe/Paris
WORKDIR /app

COPY requirements.txt .
COPY webapp/requirements.txt /tmp/webapp-requirements.txt

RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -r /tmp/webapp-requirements.txt && \
    mkdir -p data/server_scans data/alliance_scans data/player_details data/events_scans logs assets/emojis && \
    chown -R 1001:1001 /app

COPY --chown=1001:1001 . .
USER 1001

CMD ["python3", "discord_bot.py"]
