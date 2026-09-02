FROM python:3.14-slim AS gobuilder
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*
ENV GOVERSION=1.22.5
RUN curl -fsSL https://go.dev/dl/go${GOVERSION}.linux-amd64.tar.gz | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:${PATH}"
WORKDIR /src
RUN git clone --depth 1 https://github.com/OpKnock/secrets-scanner.git /src/secrets-scanner \
 && git clone --depth 1 https://github.com/OpKnock/sbom-generator-vulnerability-matcher.git /src/bomber
# apply the documented nil-context patch if not already applied
RUN cd /src/secrets-scanner && (grep -q "context.Background()" internal/cli/root.go || (sed -i 's/rootCmd.Context()/context.Background()/' internal/cli/root.go && sed -i 's/^import (/import (\n\t"context"/' internal/cli/root.go)) && (go build -trimpath -o /out/portia ./cmd/portia || go build -trimpath -o /out/portia.exe ./cmd/portia) || (go build -trimpath -o /out/portia ./cmd/portia || go build -trimpath -o /out/portia.exe ./cmd/portia)
RUN cd /src/bomber && (go build -trimpath -o /out/bomber ./cmd/bomber || go build -trimpath -o /out/bomber.exe ./cmd/bomber)
RUN mkdir -p /out && ls -lh /out || true

FROM python:3.14-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/* && \
    adduser --disabled-password --gecos '' appuser && chown -R appuser /app
COPY backend ./backend
COPY frontend ./frontend
COPY cli ./cli
COPY lab ./lab
COPY scripts ./scripts
COPY NOTICE.md README.md ./
COPY --from=gobuilder /out/ /app/bin/
RUN mkdir -p /app/database /app/evidence /app/reports && chown -R appuser /app && chmod +x /app/bin/* || true
ENV SECRETS_SCANNER_BIN=/app/bin/portia SBOM_SCANNER_BIN=/app/bin/bomber \
    PYTHONUNBUFFERED=1
EXPOSE 8000
USER appuser
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -fsS http://localhost:8000/api/health || exit 1
CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
