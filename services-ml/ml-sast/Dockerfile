FROM python:3.12-slim
# WITH_CODEBERT=1 adds torch/transformers for a CodeBERT MODEL_PATH (much larger image).
ARG WITH_CODEBERT=0
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 MODEL_PATH=/models/ml-sast/model.joblib
WORKDIR /app
COPY requirements.txt requirements-codebert.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
 && if [ "$WITH_CODEBERT" = "1" ]; then pip install --no-cache-dir -r requirements-codebert.txt --extra-index-url https://download.pytorch.org/whl/cpu; fi \
 && groupadd --gid 10001 app && useradd --uid 10001 --gid 10001 --no-create-home app
COPY --chown=10001:10001 sastml/ sastml/
COPY --chown=10001:10001 app.py .
USER 10001:10001
EXPOSE 8001
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8001/health',timeout=2)"
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8001"]
