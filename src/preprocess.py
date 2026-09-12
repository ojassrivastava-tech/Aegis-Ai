"""
Step 1: Preprocess the NSL-KDD dataset.

What this does:
1. Loads the raw NSL-KDD text files (they have no header row, so we add column names manually)
2. Converts categorical columns (protocol_type, service, flag) into numbers, since ML models
   can't work with text directly
3. Creates two label columns:
   - 'binary_label'  -> 0 (Normal) or 1 (Attack)   [for a simple normal-vs-attack model]
   - 'attack_category' -> Normal / DoS / Probe / R2L / U2R  [for identifying attack TYPE]
4. Saves clean, ready-to-train CSV files into data/
"""

import pandas as pd
from sklearn.preprocessing import LabelEncoder
import os

# NSL-KDD has 41 features + 1 label + 1 "difficulty" column, with NO header row in the raw file.
COLUMN_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty"
]

# Mapping from the ~22 specific attack names in NSL-KDD to their broader category.
# (This list covers the common ones found in KDDTrain+ / KDDTest+.)
ATTACK_CATEGORY_MAP = {
    "normal": "Normal",
    # DoS
    "back": "DoS", "land": "DoS", "neptune": "DoS", "pod": "DoS", "smurf": "DoS",
    "teardrop": "DoS", "mailbomb": "DoS", "apache2": "DoS", "processtable": "DoS", "udpstorm": "DoS",
    # Probe
    "ipsweep": "Probe", "nmap": "Probe", "portsweep": "Probe", "satan": "Probe",
    "mscan": "Probe", "saint": "Probe",
    # R2L
    "ftp_write": "R2L", "guess_passwd": "R2L", "imap": "R2L", "multihop": "R2L",
    "phf": "R2L", "spy": "R2L", "warezclient": "R2L", "warezmaster": "R2L",
    "sendmail": "R2L", "named": "R2L", "snmpgetattack": "R2L", "snmpguess": "R2L",
    "xlock": "R2L", "xsnoop": "R2L", "worm": "R2L",
    # U2R
    "buffer_overflow": "U2R", "loadmodule": "U2R", "perl": "U2R", "rootkit": "U2R",
    "httptunnel": "U2R", "ps": "U2R", "sqlattack": "U2R", "xterm": "U2R",
}


def load_and_clean(filepath):
    df = pd.read_csv(filepath, names=COLUMN_NAMES)

    # Drop the 'difficulty' column - it's a research artifact, not a real feature
    df = df.drop(columns=["difficulty"])

    # Clean label text (some versions have a trailing '.')
    df["label"] = df["label"].str.replace(".", "", regex=False).str.strip().str.lower()

    # Create the two label columns we'll actually train on
    df["attack_category"] = df["label"].map(ATTACK_CATEGORY_MAP).fillna("Unknown")
    df["binary_label"] = df["attack_category"].apply(lambda x: 0 if x == "Normal" else 1)

    return df


def encode_categorical(df, encoders=None):
    """Convert text columns (protocol_type, service, flag) into numbers.
    If `encoders` is passed (from training data), reuse the same mapping for test data."""
    categorical_cols = ["protocol_type", "service", "flag"]
    if encoders is None:
        encoders = {}
        for col in categorical_cols:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col])
            encoders[col] = le
    else:
        for col in categorical_cols:
            # Handle unseen categories in test set gracefully
            le = encoders[col]
            df[col] = df[col].apply(lambda x: x if x in le.classes_ else le.classes_[0])
            df[col] = le.transform(df[col])
    return df, encoders


if __name__ == "__main__":
    train_path = "data/KDDTrain+.txt"
    test_path = "data/KDDTest+.txt"

    if not os.path.exists(train_path) or not os.path.exists(test_path):
        print("ERROR: Dataset not found.")
        print(f"Please download NSL-KDD and place KDDTrain+.txt and KDDTest+.txt in the data/ folder.")
        print("See README.md for the download link.")
        exit(1)

    print("Loading training data...")
    train_df = load_and_clean(train_path)
    print("Loading test data...")
    test_df = load_and_clean(test_path)

    print("Encoding categorical features...")
    train_df, encoders = encode_categorical(train_df)
    test_df, _ = encode_categorical(test_df, encoders=encoders)

    os.makedirs("data", exist_ok=True)
    train_df.to_csv("data/train_processed.csv", index=False)
    test_df.to_csv("data/test_processed.csv", index=False)

    print("\nDone! Processed files saved:")
    print(" - data/train_processed.csv")
    print(" - data/test_processed.csv")
    print(f"\nTraining set: {len(train_df)} rows")
    print(f"Attack category breakdown:\n{train_df['attack_category'].value_counts()}")
