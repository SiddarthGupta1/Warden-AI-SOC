# ==========================================
# Multi-Stage Dockerfile for Sentinel AI Agent
# ==========================================

# --- Stage 1: Build React Frontend ---
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm ci --silent

COPY frontend/ ./
RUN npm run build

# --- Stage 2: Production Python Backend ---
FROM python:3.11-slim AS runtime

WORKDIR /app

# Install system utilities & security updates
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy Backend Application Code
COPY backend/app/ ./app

# Copy Built Frontend from Stage 1
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Create non-root user for enterprise AKS security standard.
# /data must exist in the image and be owned by appuser BEFORE the volume is
# mounted: Docker seeds a new named volume from the image's directory at that
# path, ownership included. Without this the volume is created root-owned and
# the non-root process cannot create its SQLite database.
RUN useradd -u 10001 -m -s /bin/sh appuser && \
    mkdir -p /data && \
    chown -R appuser:appuser /app /data
USER appuser

EXPOSE 8000

ENV APP_ENV=production \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    HOST=0.0.0.0

# Liveness probe endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/healthz || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
