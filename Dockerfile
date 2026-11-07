FROM python:3.11-slim

ENV TZ=Europe/Warsaw PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

COPY webapp/requirements.txt /tmp/webapp-requirements.txt

RUN pip install --no-cache-dir -r /tmp/webapp-requirements.txt && \
    mkdir -p data/server_scans data/alliance_scans data/player_details data/events_scans logs assets/emojis && \
    chown -R 1001:1001 /app

COPY --chown=1001:1001 . .
USER 1001

EXPOSE 8080
CMD ["python", "-m", "uvicorn", "webapp.main:app", "--host", "0.0.0.0", "--port", "8080"]
