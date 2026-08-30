FROM python:3.14-slim
WORKDIR /lab
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && \
    apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/* && \
    adduser --disabled-password --gecos '' labuser && chown -R labuser /lab
COPY lab/vulnerable-world-monitor/ .
RUN chown -R labuser /lab
ENV WM_LAB_PORT=8080 PYTHONUNBUFFERED=1
# INTENTIONALLY VULNERABLE — must never be published beyond loopback.
EXPOSE 8080
USER labuser
HEALTHCHECK --interval=30s --timeout=5s --retries=2 CMD curl -fsS http://localhost:8080/health || exit 1
CMD ["python", "app.py"]
