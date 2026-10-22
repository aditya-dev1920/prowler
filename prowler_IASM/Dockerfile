# Prowler IASM Microservice Dockerfile
# Lightweight, single-container production scanner & REST API
FROM python:3.11-slim-bookworm

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_DEFAULT_TIMEOUT=120 \
    PORT=3755

# Install minimal OS dependencies required for scans, compression, and healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    curl \
    jq \
    zip \
    unzip \
    ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency definition first for optimal Docker layer caching
COPY requirements.txt /app/

# Configure pip for corporate proxy / SSL inspection environments and install dependencies
# Uses BuildKit cache mount (/root/.cache/pip) to persist downloaded wheels across future rebuilds
RUN --mount=type=cache,target=/root/.cache/pip \
    pip config set global.trusted-host "pypi.org pypi.python.org files.pythonhosted.org" && \
    pip install \
        --trusted-host pypi.org \
        --trusted-host pypi.python.org \
        --trusted-host files.pythonhosted.org \
        --upgrade pip && \
    pip install \
        --trusted-host pypi.org \
        --trusted-host pypi.python.org \
        --trusted-host files.pythonhosted.org \
        -r requirements.txt

# Copy application source code and scripts
COPY . /app/

# Make the runner script executable and prepare scan output directory
RUN chmod +x /app/run_scan.sh && \
    mkdir -p /app/scan_results

# Expose REST API (3755) and optional Streamlit UI (8501)
EXPOSE 3755 8501

# Healthcheck to ensure microservice readiness
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:3755/health || exit 1

# Default command launches the FastAPI microservice
CMD ["uvicorn", "src.api.api:app", "--host", "0.0.0.0", "--port", "3755"]
