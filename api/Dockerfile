FROM python:3.11-slim

WORKDIR /app

COPY api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY api/ ./api/
COPY src/generate_report.py ./src/generate_report.py
COPY models/ ./models/

EXPOSE 8000

CMD ["uvicorn", "api.ml_service:app", "--host", "0.0.0.0", "--port", "8000"]
