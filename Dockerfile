FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080

WORKDIR /app

COPY app ./app
COPY tests ./tests
COPY verify ./verify

RUN useradd --system --uid 10001 --home-dir /app audit \
    && chown -R audit:audit /app
USER audit

EXPOSE 8080

HEALTHCHECK --interval=3s --timeout=3s --start-period=5s --retries=20 \
    CMD ["python", "-m", "app.healthcheck"]

CMD ["python", "-m", "app.server"]
