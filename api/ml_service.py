"""
ML Service (FastAPI) — wraps our trained model + SHAP explainer + report
generator into a single HTTP API. This is the "brain" of the system.

Run with: uvicorn api.ml_service:app --host 0.0.0.0 --port 8000
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pandas as pd
import numpy as np
import joblib
import shap
import sys
import os

# Allow importing generate_report.py from src/
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))
from generate_report import build_report

app = FastAPI(title="NIDS ML Service")

# Allow the dashboard (running on a different port) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "nids_model.pkl")
FEATURES_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "feature_columns.pkl")

model = joblib.load(MODEL_PATH)
feature_columns = joblib.load(FEATURES_PATH)
explainer = shap.TreeExplainer(model)


class TrafficRecord(BaseModel):
    # One record = one network connection's features.
    # All 41 NSL-KDD features, matching src/train_model.py's FEATURE_COLUMNS.
    duration: float = 0
    protocol_type: int = 0
    service: int = 0
    flag: int = 0
    src_bytes: float = 0
    dst_bytes: float = 0
    land: int = 0
    wrong_fragment: int = 0
    urgent: int = 0
    hot: int = 0
    num_failed_logins: int = 0
    logged_in: int = 0
    num_compromised: int = 0
    root_shell: int = 0
    su_attempted: int = 0
    num_root: int = 0
    num_file_creations: int = 0
    num_shells: int = 0
    num_access_files: int = 0
    num_outbound_cmds: int = 0
    is_host_login: int = 0
    is_guest_login: int = 0
    count: float = 0
    srv_count: float = 0
    serror_rate: float = 0
    srv_serror_rate: float = 0
    rerror_rate: float = 0
    srv_rerror_rate: float = 0
    same_srv_rate: float = 0
    diff_srv_rate: float = 0
    srv_diff_host_rate: float = 0
    dst_host_count: float = 0
    dst_host_srv_count: float = 0
    dst_host_same_srv_rate: float = 0
    dst_host_diff_srv_rate: float = 0
    dst_host_same_src_port_rate: float = 0
    dst_host_srv_diff_host_rate: float = 0
    dst_host_serror_rate: float = 0
    dst_host_srv_serror_rate: float = 0
    dst_host_rerror_rate: float = 0
    dst_host_srv_rerror_rate: float = 0

    class Config:
        extra = "ignore"


def get_shap_explanation(sample_df):
    """Returns top 5 (feature, impact, value) tuples explaining the prediction."""
    shap_values = explainer.shap_values(sample_df)

    if isinstance(shap_values, list):
        values_for_attack_class = shap_values[1][0]
    else:
        shap_values = np.array(shap_values)
        if shap_values.ndim == 3:
            values_for_attack_class = shap_values[0, :, 1]
        else:
            values_for_attack_class = shap_values[0]

    values_for_attack_class = np.ravel(values_for_attack_class)
    feature_impact = list(zip(feature_columns, values_for_attack_class, sample_df.iloc[0].values))
    feature_impact.sort(key=lambda x: abs(float(x[1])), reverse=True)
    return feature_impact[:5]


@app.get("/")
def root():
    return {"status": "NIDS ML Service is running", "model": "RandomForestClassifier"}


@app.post("/predict")
def predict(record: TrafficRecord):
    sample_df = pd.DataFrame([record.dict()])[feature_columns]

    prediction = model.predict(sample_df)[0]
    probability = model.predict_proba(sample_df)[0]
    confidence = float(max(probability))

    result = {
        "prediction": "Attack" if prediction == 1 else "Normal",
        "confidence": round(confidence, 4),
    }

    if prediction == 1:
        feature_impact = get_shap_explanation(sample_df)
        result["top_reasons"] = [
            {"feature": f, "impact": round(float(i), 4), "value": float(v)}
            for f, i, v in feature_impact
        ]
        # We don't know the *specific* attack category here (that needs the
        # multi-class model), so we label it generically for the live API.
        report = build_report(feature_impact, "Attack")
        result["report"] = report

    return result
