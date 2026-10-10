FROM node:22-alpine AS frontend-builder

WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies required by lxml/trafilatura
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libxml2-dev \
        libxslt1-dev \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Release metadata changes on every deployment. Keep it after dependency
# installation so a new Git SHA does not invalidate the expensive pip layer.
ARG TW_BUILD_SHA=unknown
ARG TW_BUILD_TIME=unknown
ENV TW_BUILD_SHA=${TW_BUILD_SHA} \
    TW_BUILD_TIME=${TW_BUILD_TIME}

# Copy application source and the immutable frontend build.
COPY threatdigest_main.py serve_threatwatch.py favicon.svg ./
COPY modules/ modules/
COPY config/ config/
COPY app/ app/
COPY scripts/ scripts/
COPY --from=frontend-builder /build/frontend/dist/ frontend/dist/

# Create data directory structure
RUN mkdir -p data/output/hourly data/output/daily \
             data/state/ai_cache \
             data/logs/run_logs data/logs/summaries

# Run as non-root for container security
RUN adduser --disabled-password --gecos '' --uid 1001 appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8098

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8098/ || exit 1

# Default command (overridden by docker-compose per service)
CMD ["python", "serve_threatwatch.py"]
