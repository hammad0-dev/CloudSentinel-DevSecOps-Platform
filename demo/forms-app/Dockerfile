FROM python:3.12-slim
RUN groupadd --gid 1000 app && useradd --uid 1000 --gid app --no-create-home app
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=1000:1000 app.py .
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DEMO_DB_PATH=/tmp/catalogue.db
EXPOSE 8080
USER 1000:1000
# The root filesystem is read-only in staging; the database and gunicorn's worker files live in /tmp.
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "4", "--worker-tmp-dir", "/tmp", "app:app"]
