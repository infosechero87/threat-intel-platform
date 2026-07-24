FROM python:3.12-slim

LABEL org.opencontainers.image.title="Threat Intelligence Platform"
LABEL org.opencontainers.image.description="Real-time cyber threat intelligence dashboard with dark web search, Telegram monitoring, and credential checking"

RUN apt-get update \
    && apt-get install -y --no-install-recommends tor \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash --uid 1000 threatintel

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chown -R threatintel:threatintel /app

USER threatintel
EXPOSE 8000

ENV FLASK_HOST=0.0.0.0
ENV FLASK_PORT=8000

CMD ["python3", "-m", "gunicorn", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "2", \
     "--worker-class", "gevent", \
     "--worker-connections", "500", \
     "--timeout", "120", \
     "--preload", \
     "wsgi:app"]
