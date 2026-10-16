# Prowler IASM Microservice Dockerfile
# Lightweight, single-container production scanner & REST API
FROM python:3.11-slim-bookworm

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    PORT=8000

# Install minimal OS dependencies required for scans, compression, and healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    curl \
    jq \
    zip \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency definition first for optimal Docker layer caching
COPY requirements.txt /app/

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code and scripts
COPY . /app/

# Make the runner script executable and prepare scan output directory
RUN chmod +x /app/run_scan.sh && \
    mkdir -p /app/scan_results

# Expose REST API (8000) and optional Streamlit UI (8501)
EXPOSE 8000 8501

# Healthcheck to ensure microservice readiness
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command launches the FastAPI microservice
CMD ["uvicorn", "src.api.api:app", "--host", "0.0.0.0", "--port", "8000"]

