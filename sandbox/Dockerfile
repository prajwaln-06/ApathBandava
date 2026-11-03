# Isolated URL detonation service. Runs on sandbox_net only (see docker-compose.yml).
FROM mcr.microsoft.com/playwright/python:v1.55.0-noble
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN apt-get update && apt-get install -y --no-install-recommends iptables util-linux \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py entrypoint.sh ./
RUN chmod 0755 /app/entrypoint.sh && mkdir -p /shots && chown pwuser /shots
EXPOSE 9000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=5 \
  CMD python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:9000/health',timeout=2)"
ENTRYPOINT ["/app/entrypoint.sh"]
