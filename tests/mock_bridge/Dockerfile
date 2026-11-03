FROM python:3.12-slim
RUN pip install --no-cache-dir fastapi==0.115.12 uvicorn==0.34.2 && useradd -r -u 10004 mock
WORKDIR /app
COPY app.py .
USER mock
HEALTHCHECK --interval=10s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8090/api/health',timeout=2)"
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8090", "--no-access-log"]
