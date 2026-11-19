FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 MODEL_PATH=/models/ml-dast/model.joblib
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && groupadd --gid 10001 app && useradd --uid 10001 --gid 10001 --no-create-home app
COPY --chown=10001:10001 app.py .
USER 10001:10001
EXPOSE 8002
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8002/health',timeout=2)"
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8002"]
