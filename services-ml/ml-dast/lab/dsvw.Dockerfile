# DSVW (stamparm/DSVW @ 9ca3c9a, Unlicense): the v2 FINAL HELD-OUT app. LAB ONLY, 127.0.0.1 only.
# Never used for training or tuning; collected and scored once by scripts/eval_final_v2.py.
FROM python:3.12-slim
RUN pip install --no-cache-dir lxml==5.3.0 && useradd --uid 10001 --no-create-home dsvw
WORKDIR /dsvw
COPY dsvw.py .
USER 10001
EXPOSE 8080
CMD ["python3", "dsvw.py", "--host=0.0.0.0", "--port=8080"]
