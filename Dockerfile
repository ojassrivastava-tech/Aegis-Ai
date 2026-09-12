# ==============================================================================
# AEGIS AI SOC PLATFORM — ALL-IN-ONE PRODUCTION CLOUD CONTAINER
# Runs both Python FastAPI ML Microservice & Node.js 24 Real-Time WebSockets
# ==============================================================================
FROM node:24-bookworm-slim

# Install Python 3, pip, and required system libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 1. Install Python ML dependencies
COPY api/requirements.txt ./api/
RUN pip3 install --no-cache-dir -r api/requirements.txt --break-system-packages

# 2. Install Node.js Backend dependencies
COPY server/package.json ./server/
RUN cd server && npm install --omit=dev

# 3. Copy application codebase and ML models
COPY api/ ./api/
COPY src/ ./src/
COPY models/ ./models/
COPY data/ ./data/
COPY dashboard/ ./dashboard/
COPY server/ ./server/

# Production Environment Settings
ENV PORT=4000
ENV ML_SERVICE_URL=http://127.0.0.1:8000
ENV NODE_ENV=production

EXPOSE 4000

# Copy and setup production startup runner
COPY start.sh ./start.sh
RUN chmod +x ./start.sh

CMD ["./start.sh"]
