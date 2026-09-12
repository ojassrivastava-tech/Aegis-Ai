"""
Step 3: Explain WHY a specific network connection was flagged as an attack.

This is the part that makes your project different from a generic tutorial NIDS:
most student projects just say "Attack Detected". This one says WHICH features
made the model think so, using SHAP (SHapley Additive exPlanations) - an
industry-standard technique for explaining ML predictions.
"""

import pandas as pd
import numpy as np
import joblib
import shap

if __name__ == "__main__":
    print("Loading model and data...")
    model = joblib.load("models/nids_model.pkl")
    feature_columns = joblib.load("models/feature_columns.pkl")
    test_df = pd.read_csv("data/test_processed.csv")

    X_test = test_df[feature_columns]

    # Find one row that the model predicts as an ATTACK, to explain as an example
    predictions = model.predict(X_test)
    attack_indices = [i for i, p in enumerate(predictions) if p == 1]

    if not attack_indices:
        print("No attacks found in test predictions to explain. Try a different sample.")
        exit(0)

    sample_index = attack_indices[0]
    sample = X_test.iloc[[sample_index]]

    print(f"\nExplaining prediction for row #{sample_index} "
          f"(true label: {'Attack' if test_df['binary_label'].iloc[sample_index] == 1 else 'Normal'}, "
          f"category: {test_df['attack_category'].iloc[sample_index]})")

    # Build SHAP explainer (TreeExplainer is fast and made for tree-based models like Random Forest)
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(sample)

    # Different SHAP library versions return this in different shapes, so handle all of them:
    # - list of arrays (older versions): [class_0_values, class_1_values]
    # - 3D array (newer versions): (n_samples, n_features, n_classes)
    # - 2D array: (n_samples, n_features)
    if isinstance(shap_values, list):
        values_for_attack_class = shap_values[1][0]
    else:
        shap_values = np.array(shap_values)
        if shap_values.ndim == 3:
            values_for_attack_class = shap_values[0, :, 1]
        else:
            values_for_attack_class = shap_values[0]

    values_for_attack_class = np.ravel(values_for_attack_class)

    # Pair each feature with its SHAP value (how much it pushed the prediction toward "Attack")
    feature_impact = list(zip(feature_columns, values_for_attack_class, sample.iloc[0].values))
    feature_impact.sort(key=lambda x: abs(float(x[1])), reverse=True)

    print("\nTop 5 features that influenced this decision:")
    for feature_name, impact, value in feature_impact[:5]:
        direction = "pushed toward ATTACK" if impact > 0 else "pushed toward NORMAL"
        print(f"  - {feature_name} = {value}  ({direction}, impact score: {impact:.4f})")

    # Save this info so generate_report.py can turn it into plain English
    joblib.dump(feature_impact[:5], "models/last_explanation.pkl")
    joblib.dump(test_df['attack_category'].iloc[sample_index], "models/last_attack_category.pkl")

    print("\nSaved explanation. Next: run 'python src/generate_report.py' for a plain-English summary.")
