FROM python:3.11-slim

LABEL org.opencontainers.image.title="Threat Intelligence Platform"
LABEL org.opencontainers.image.description="Real-time cyber threat intelligence dashboard"

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-tk \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

ENV FLASK_HOST=0.0.0.0
ENV FLASK_PORT=5000

CMD ["python3", "app.py"]
