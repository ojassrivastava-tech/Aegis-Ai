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
    attack_category: str = ""
    attack_type: str = ""
    mitre_name: str = ""
    mitre_tactic: str = ""

    class Config:
        extra = "ignore"


def get_shap_explanation(sample_df):
    """
    Computes SHAP values for a single prediction and returns the top 5
    features that pushed the prediction toward "Attack", sorted by impact.
    """
    shap_values = explainer.shap_values(sample_df)

    if isinstance(shap_values, list):
        # Multi-output / older SHAP format: index 1 is usually the "Attack" class
        values_for_attack_class = shap_values[1] if len(shap_values) > 1 else shap_values[0]
    else:
        # Newer SHAP format: 3D array (samples, features, classes)
        if len(shap_values.shape) == 3:
            values_for_attack_class = shap_values[:, :, 1]
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
    record_dict = record.model_dump() if hasattr(record, "model_dump") else record.dict()
    sample_df = pd.DataFrame([record_dict])[feature_columns]

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
        
        # Determine specific attack category and MITRE mapping
        category = record.mitre_name or record.attack_category
        if not category or category in ["Attack", "0", "Unknown"]:
            top_f = [f[0] for f in feature_impact]
            if record.wrong_fragment > 0 or "wrong_fragment" in top_f:
                category = "Fragment Evasion (MITRE T1027)"
            elif record.root_shell > 0 or record.num_root > 0 or "root_shell" in top_f:
                category = "User-to-Root Exploitation (MITRE T1068)"
            elif record.num_failed_logins > 0 or record.is_guest_login > 0 or "num_failed_logins" in top_f:
                category = "Brute Force Password Guessing (MITRE T1110)"
            elif record.dst_host_diff_srv_rate > 0.25 or "dst_host_diff_srv_rate" in top_f:
                category = "Port Scanning / Probe (MITRE T1595)"
            elif record.serror_rate > 0.4 or record.count > 60:
                category = "Network DoS Flood (MITRE T1498)"
            else:
                category = "Exploit Public-Facing App (MITRE T1190)"

        result["attack_category"] = category
        report = build_report(feature_impact, category)
        result["report"] = report

    return result
