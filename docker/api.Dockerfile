FROM python:3.14-slim AS gobuilder
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*
ENV GOVERSION=1.26.4
RUN curl -fsSL https://go.dev/dl/go${GOVERSION}.linux-amd64.tar.gz | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:${PATH}"
WORKDIR /src
COPY candidates/ /candidates/
RUN git clone --depth 1 https://github.com/OpKnock/secrets-scanner.git /src/secrets-scanner \
 && git clone --depth 1 https://github.com/OpKnock/sbom-generator-vulnerability-matcher.git /src/bomber \
 || true
# apply the documented nil-context patch if not already applied
RUN if [ -f /candidates/secrets-scanner/internal/cli/root.go ]; then cp -r /candidates/secrets-scanner /src/secrets-scanner; fi; \
    cd /src/secrets-scanner && \
    grep -q "context.Background()" internal/cli/root.go || \
    (sed -i 's/rootCmd.Context()/context.Background()/' internal/cli/root.go && \
     sed -i 's/^import (/import (\n\t"context"/' internal/cli/root.go) && \
    go build -trimpath -o /out/portia.exe ./cmd/portia || go build -trimpath -o /out/portia ./cmd/portia; \
    cd /src/bomber && go build -trimpath -o /out/bomber.exe ./cmd/bomber || go build -trimpath -o /out/bomber ./cmd/bomber

FROM python:3.14-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend ./backend
COPY frontend ./frontend
COPY cli ./cli
COPY lab ./lab
COPY scripts ./scripts
COPY NOTICE.md README.md ./
COPY --from=gobuilder /out/ /app/bin/
ENV SECRETS_SCANNER_BIN=/app/bin/portia SBOM_SCANNER_BIN=/app/bin/bomber \
    PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
