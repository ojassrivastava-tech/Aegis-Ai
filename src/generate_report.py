"""
Step 4: Turn the technical SHAP explanation into a plain-English incident report
that a non-technical manager could understand.

This is a template-based version (no external AI API needed, so it works for free
and offline). If you want to make it even fancier later, you can swap the
`build_report()` function to call an LLM API (like Anthropic's or OpenAI's) and
pass it the same feature_impact data, asking it to write the summary instead.
"""

import joblib

# Human-friendly descriptions for technical feature names.
# (Add more as you explore other features — this covers the most common ones.)
FEATURE_DESCRIPTIONS = {
    "count": "the number of connections made to the same host recently",
    "srv_count": "the number of connections made to the same service recently",
    "serror_rate": "the rate of connection errors (failed handshakes)",
    "srv_serror_rate": "the rate of service-level connection errors",
    "dst_host_count": "how many connections were made to the destination host",
    "dst_host_srv_count": "how many connections were made to the same service on the destination host",
    "dst_host_same_srv_rate": "how often the destination host was accessed via the same service",
    "dst_host_diff_srv_rate": "how often the destination host was accessed via different services",
    "src_bytes": "the amount of data sent from source to destination",
    "dst_bytes": "the amount of data sent from destination back to source",
    "duration": "how long the connection lasted",
    "logged_in": "whether the connection was successfully logged in",
    "num_failed_logins": "the number of failed login attempts",
    "wrong_fragment": "the number of malformed data fragments",
    "flag": "the connection status flag (e.g. normal close, reset, rejected)",
    "protocol_type": "the network protocol used (TCP/UDP/ICMP)",
    "same_srv_rate": "how often the same service was repeatedly accessed",
    "diff_srv_rate": "how often different services were accessed in quick succession",
}


def describe_feature(name):
    return FEATURE_DESCRIPTIONS.get(name, name.replace("_", " "))


def build_report(feature_impact, attack_category):
    top_reasons = [f for f in feature_impact if f[1] > 0][:3]  # only reasons pushing toward "Attack"

    if not top_reasons:
        return "This connection showed borderline characteristics but was ultimately classified as an attack based on a combination of minor factors."

    reason_sentences = []
    for feature_name, impact, value in top_reasons:
        reason_sentences.append(f"{describe_feature(feature_name)} (recorded value: {value})")

    report = (
        f"INCIDENT REPORT\n"
        f"{'-' * 50}\n"
        f"Classification: Suspicious Activity Detected\n"
        f"Likely Category: {attack_category}\n\n"
        f"Summary: This network connection was flagged as a potential "
        f"'{attack_category}' attack. The main factors that led to this "
        f"decision were:\n"
    )
    for i, sentence in enumerate(reason_sentences, 1):
        report += f"  {i}. {sentence}\n"

    report += (
        f"\nRecommended Action: Review the source of this connection. If this "
        f"pattern repeats, consider temporarily blocking the source and "
        f"investigating further.\n"
    )
    return report


if __name__ == "__main__":
    feature_impact = joblib.load("models/last_explanation.pkl")
    attack_category = joblib.load("models/last_attack_category.pkl")

    report = build_report(feature_impact, attack_category)
    print(report)

    with open("models/latest_incident_report.txt", "w") as f:
        f.write(report)

    print("\nSaved to models/latest_incident_report.txt")
