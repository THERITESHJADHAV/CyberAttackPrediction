import requests
import json
import os

ML_URL = "http://localhost:8080/predict"

test_vectors = {
    "Normal HTTP flow": {
        "duration": 2.0, "src_bytes": 500, "dst_bytes": 5000,
        "protocol_type": "tcp", "service": "http", "flag": "SF",
        "logged_in": 1.0, "count": 1, "srv_count": 1,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "dst_host_count": 5, "dst_host_srv_count": 5,
        "dst_host_same_srv_rate": 1.0, "dst_host_diff_srv_rate": 0.0,
        "dst_host_serror_rate": 0.0, "dst_host_rerror_rate": 0.0,
    },
    "DOS Neptune (SYN flood)": {
        "duration": 0.0, "src_bytes": 0, "dst_bytes": 0,
        "protocol_type": "tcp", "service": "http", "flag": "S0",
        "logged_in": 0.0, "count": 200, "srv_count": 200,
        "serror_rate": 1.0, "srv_serror_rate": 1.0,
        "rerror_rate": 0.0, "srv_rerror_rate": 0.0,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "dst_host_count": 255, "dst_host_srv_count": 255,
        "dst_host_same_srv_rate": 1.0, "dst_host_diff_srv_rate": 0.0,
        "dst_host_serror_rate": 1.0, "dst_host_srv_serror_rate": 1.0,
    },
    "Probe Portsweep": {
        "duration": 0.0, "src_bytes": 0, "dst_bytes": 0,
        "protocol_type": "tcp", "service": "other", "flag": "REJ",
        "logged_in": 0.0, "count": 100, "srv_count": 10,
        "serror_rate": 0.0, "rerror_rate": 1.0, "srv_rerror_rate": 1.0,
        "same_srv_rate": 0.1, "diff_srv_rate": 0.9,
        "dst_host_count": 255, "dst_host_srv_count": 1,
        "dst_host_same_srv_rate": 0.01, "dst_host_diff_srv_rate": 0.99,
        "dst_host_rerror_rate": 1.0, "dst_host_srv_rerror_rate": 1.0,
    },
    "HTTP flood with high count": {
        "duration": 0.01, "src_bytes": 300, "dst_bytes": 1000,
        "protocol_type": "tcp", "service": "http", "flag": "SF",
        "logged_in": 1.0, "count": 150, "srv_count": 150,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "dst_host_count": 200, "dst_host_srv_count": 200,
        "dst_host_same_srv_rate": 1.0, "dst_host_diff_srv_rate": 0.0,
        "dst_host_same_src_port_rate": 0.05,
    },
    "SQLi (Low count, payload attack)": {
        "duration": 0.1, "src_bytes": 400, "dst_bytes": 2000,
        "protocol_type": "tcp", "service": "http", "flag": "SF",
        "logged_in": 1.0, "count": 5, "srv_count": 5,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "dst_host_count": 10, "dst_host_srv_count": 10,
        "dst_host_same_srv_rate": 1.0, "dst_host_diff_srv_rate": 0.0,
    },
}

with open("ml_test_results.txt", "w", encoding="utf-8") as f:
    f.write("=" * 70 + "\n")
    f.write("ML MODEL ATTACK DETECTION TEST\n")
    f.write("=" * 70 + "\n")

    for name, features in test_vectors.items():
        try:
            resp = requests.post(ML_URL, json=features, timeout=5)
            if resp.status_code == 200:
                result = resp.json()
                is_attack = result.get('prediction', 0)
                prob = result.get('attack_probability', 0)
                label = result.get('predicted_label', '?')
                icon = "ATTACK" if is_attack else "NORMAL"
                f.write(f"\n{icon} | {name}\n")
                f.write(f"   Label: {label} | Attack prob: {prob:.4f} | Confidence: {result.get('confidence', 0):.4f}\n")
            else:
                f.write(f"\nERROR | {name}: {resp.status_code}\n")
        except Exception as e:
            f.write(f"\nERROR | {name}: {e}\n")
