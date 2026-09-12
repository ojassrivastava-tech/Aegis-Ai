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

if __name__ == "__main__":
    print("Loading processed data...")
    train_df = pd.read_csv("data/train_processed.csv")
    test_df = pd.read_csv("data/test_processed.csv")

    X_train = train_df[FEATURE_COLUMNS]
    y_train = train_df["binary_label"]
    X_test = test_df[FEATURE_COLUMNS]
    y_test = test_df["binary_label"]

    print(f"Training on {len(X_train)} samples, testing on {len(X_test)} samples...")

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)

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
