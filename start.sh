#!/bin/bash
set -e

echo "=================================================================="
echo "🛡️  STARTING AEGIS AI CLOUD PRODUCTION STACK"
echo "=================================================================="

# 1. Start Python FastAPI ML Inference Microservice on Port 8000
echo "[+] Starting Python ML Service on http://127.0.0.1:8000..."
python3 -m uvicorn api.ml_service:app --host 0.0.0.0 --port 8000 &
ML_PID=$!

# 2. Wait briefly for ML engine to load Scikit-Learn / SHAP models
sleep 3

# 3. Start Node.js Real-Time Gateway & Dashboard on $PORT (Default: 4000)
echo "[+] Starting AEGIS SOC Platform on port ${PORT:-4000}..."
cd /app/server
exec node server.js
