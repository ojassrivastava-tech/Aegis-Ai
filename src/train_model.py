"""
Step 2: Train a Random Forest model to detect attacks.

What this does:
1. Loads the processed train/test CSVs from Step 1
2. Trains a RandomForestClassifier to predict binary_label (Normal vs Attack)
3. Evaluates it: accuracy, precision, recall, f1-score (these numbers go in your
   report/presentation to show how well the model performs)
4. Saves the trained model so we can reuse it later (for explaining predictions,
   building the API, etc.) without retraining every time
"""

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import os

FEATURE_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]

MODEL_CANDIDATES = {
    "RandomForest": lambda: RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1),
    "DecisionTree": lambda: DecisionTreeClassifier(max_depth=15, random_state=42),
}

def evaluate_model(model, X, y):
    y_pred = model.predict(X)
    return {
        "accuracy": float(accuracy_score(y, y_pred)),
        "confusion_matrix": confusion_matrix(y, y_pred),
        "report": classification_report(y, y_pred, zero_division=0)
    }

def select_best_model(X, y):
    best_name = None
    best_model = None
    best_acc = -1.0
    for name, factory in MODEL_CANDIDATES.items():
        candidate = factory()
        candidate.fit(X, y)
        metrics = evaluate_model(candidate, X, y)
        if metrics["accuracy"] > best_acc:
            best_acc = metrics["accuracy"]
            best_name = name
            best_model = candidate
    return best_name, best_model

def build_explainer(model, X=None):
    import shap
    import numpy as np

    if hasattr(model, "estimators_") or hasattr(model, "tree_") or "Tree" in type(model).__name__:
        try:
            return shap.TreeExplainer(model)
        except Exception:
            pass

    X_arr = np.array(X) if X is not None else None
    if hasattr(shap, "LinearExplainer") and ("Linear" in type(model).__name__ or "Logistic" in type(model).__name__):
        try:
            return shap.LinearExplainer(model, X_arr)
        except Exception:
            pass

    try:
        return shap.Explainer(model, X_arr)
    except Exception:
        predict_fn = model.predict_proba if hasattr(model, "predict_proba") else model.predict
        background = X_arr[:5] if X_arr is not None else None
        return shap.KernelExplainer(predict_fn, background)

if __name__ == "__main__":
    print("Loading processed data...")
    if os.path.exists("data/train_processed.csv"):
        train_df = pd.read_csv("data/train_processed.csv")
        test_df = pd.read_csv("data/test_processed.csv")
        X_train = train_df[FEATURE_COLUMNS]
        y_train = train_df["binary_label"]
        X_test = test_df[FEATURE_COLUMNS]
        y_test = test_df["binary_label"]
    elif os.path.exists("data/test_processed.csv"):
        print("Note: data/train_processed.csv not found. Partitioning data/test_processed.csv for training...")
        from sklearn.model_selection import train_test_split
        full_df = pd.read_csv("data/test_processed.csv")
        train_df, test_df = train_test_split(full_df, test_size=0.25, random_state=42, stratify=full_df["binary_label"])
        X_train = train_df[FEATURE_COLUMNS]
        y_train = train_df["binary_label"]
        X_test = test_df[FEATURE_COLUMNS]
        y_test = test_df["binary_label"]
    else:
        raise FileNotFoundError("No processed dataset found in data/. Run src/preprocess.py first.")

    print(f"Training on {len(X_train)} samples, testing on {len(X_test)} samples...")

    best_name, model = select_best_model(X_train, y_train)
    print(f"Selected candidate model: {best_name}")

    print("\nEvaluating model...")
    y_pred = model.predict(X_test)

    print(f"\nAccuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # Save model + feature list + test data for the explain step
    os.makedirs("models", exist_ok=True)
    joblib.dump(model, "models/nids_model.pkl")
    joblib.dump(FEATURE_COLUMNS, "models/feature_columns.pkl")

    print("\nModel saved to models/nids_model.pkl")
    print("Next: run 'python src/explain.py' to see WHY a specific detection was flagged.")
