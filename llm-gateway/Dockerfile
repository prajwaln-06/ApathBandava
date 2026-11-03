FROM python:3.12-slim
RUN useradd -r -u 10001 app
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY gateway.py .
USER app
EXPOSE 4000
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:4000/health',timeout=2)"
CMD ["uvicorn", "gateway:app", "--host", "0.0.0.0", "--port", "4000", "--no-access-log"]
