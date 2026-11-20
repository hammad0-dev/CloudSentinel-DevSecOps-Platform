# LAB ONLY: vulpy (https://github.com/fportantier/vulpy, MIT) at commit 5249cc8, bad or good variant.
# Bound to 0.0.0.0 inside the container (published on 127.0.0.1 by compose); Flask debug off so the
# Werkzeug console is not reachable.
FROM python:3.12-slim
ARG VARIANT=bad
RUN pip install --no-cache-dir flask==3.0.3 passlib==1.7.4 pyotp==2.9.0 qrcode==7.4.2 PyJWT==2.9.0 \
    cryptography==43.0.3 jsonschema==4.23.0 requests==2.32.3 click==8.1.7 geoip2==4.8.1
WORKDIR /app
COPY ${VARIANT}/ /app/
RUN sed -i "s/host='127.0.1.1'/host='0.0.0.0'/; s/port=500[01]/port=5000/; s/debug=True/debug=False/" vulpy.py \
 && python db_init.py && chown -R nobody /app
USER nobody
EXPOSE 5000
CMD ["python", "vulpy.py"]
