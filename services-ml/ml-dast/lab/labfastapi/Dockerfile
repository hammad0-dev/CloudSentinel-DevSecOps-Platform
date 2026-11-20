# LAB ONLY: deliberately vulnerable app for ml-dast ground truth. Never deploy.
FROM python:3.12-slim
RUN pip install --no-cache-dir fastapi==0.115.12 uvicorn==0.34.2 pymysql==1.1.1 jinja2==3.1.4 python-multipart==0.0.20
WORKDIR /app
COPY app.py .
USER nobody
EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
