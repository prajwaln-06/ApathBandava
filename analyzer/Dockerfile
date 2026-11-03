FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends \
      tesseract-ocr tesseract-ocr-eng tesseract-ocr-hin libzbar0 libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/* && useradd -r -u 10003 analyzer
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY weights.yaml .
USER analyzer
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=30s --retries=5 \
  CMD python -c "import urllib.request,json,sys;d=json.load(urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=2));sys.exit(0 if d['ready'] else 1)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]

FROM runtime AS test
USER root
COPY requirements-dev.txt .coveragerc ./
RUN pip install --no-cache-dir -r requirements-dev.txt
USER analyzer
CMD ["pytest"]
