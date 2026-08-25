FROM python:3.14-slim
WORKDIR /lab
COPY lab/vulnerable-world-monitor/ .
ENV WM_LAB_PORT=8080 PYTHONUNBUFFERED=1
# INTENTIONALLY VULNERABLE — must never be published beyond loopback.
EXPOSE 8080
CMD ["python", "app.py"]
