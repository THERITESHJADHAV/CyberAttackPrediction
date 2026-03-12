"""
ML WEB SERVICE — Random Forest Attack Prediction API
=====================================================
Loads the trained Random Forest model and provides HTTP endpoints
for real-time network attack prediction.

Endpoints:
    POST /predict  — Predict if network traffic is an attack
    GET  /health   — Health check
"""

from flask import Flask, request, jsonify  # type: ignore
import numpy as np  # type: ignore
import pandas as pd  # type: ignore
import joblib  # type: ignore
import logging
import os
from datetime import datetime
from typing import Any

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =============================================================================
# Global model instances — loaded at startup
# =============================================================================
rf_model: Any = None
scaler: Any = None
label_encoder: Any = None
feature_columns: Any = None

ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), 'rf_artifacts')

# The 38 numeric KDD features (before one-hot encoding)
KDD_NUMERIC_FEATURES = [
    'duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent',
    'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
    'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login',
    'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
    'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate'
]

# The 3 categorical KDD features
KDD_CATEGORICAL_FEATURES = ['protocol_type', 'service', 'flag']


def load_models():
    """Load all trained model artifacts at startup."""
    global rf_model, scaler, label_encoder, feature_columns

    try:
        logger.info("🔄 Loading Random Forest model artifacts...")

        rf_model = joblib.load(os.path.join(ARTIFACTS_DIR, 'rf_model.pkl'))
        logger.info("   ✅ Random Forest model loaded")

        scaler = joblib.load(os.path.join(ARTIFACTS_DIR, 'scaler.pkl'))
        logger.info("   ✅ StandardScaler loaded")

        label_encoder = joblib.load(os.path.join(ARTIFACTS_DIR, 'label_encoder.pkl'))
        logger.info(f"   ✅ LabelEncoder loaded (classes: {list(label_encoder.classes_)})")

        feature_columns = joblib.load(os.path.join(ARTIFACTS_DIR, 'feature_columns.pkl'))
        logger.info(f"   ✅ Feature columns loaded ({len(feature_columns)} features)")

        logger.info("🎉 All models loaded successfully!")
        return True
    except Exception as e:
        logger.error(f"❌ Failed to load models: {e}")
        return False


def map_raw_to_kdd(raw_data: dict) -> pd.DataFrame:
    """
    Map raw network flow data from the agent to a KDD-format DataFrame.
    
    The agent sends raw packet features. This function:
    1. Extracts numeric KDD features (defaults to 0.0 if missing)
    2. Extracts categorical features (protocol_type, service, flag)
    3. One-hot encodes the categorical features
    4. Aligns to the exact training column order
    """
    # Build a single-row dict of numeric features
    row = {}
    for feat in KDD_NUMERIC_FEATURES:
        row[feat] = float(raw_data.get(feat, 0.0))

    # Build categorical features
    protocol = raw_data.get('protocol_type', 'tcp').lower()
    service = raw_data.get('service', 'http').lower()
    flag = raw_data.get('flag', 'SF').upper()

    row['protocol_type'] = protocol
    row['service'] = service
    row['flag'] = flag

    # Create DataFrame and one-hot encode
    df = pd.DataFrame([row])
    df = pd.get_dummies(df)

    # Align to exact training columns — fill missing with 0
    assert feature_columns is not None
    for col in feature_columns:
        if col not in df.columns:
            df[col] = 0

    # Ensure exact column order
    df = df[feature_columns]

    return df


@app.route('/predict', methods=['POST'])
def predict_attack():
    """Predict if network traffic is an attack using Random Forest."""
    try:
        raw_data = request.json
        src_ip = raw_data.get('srcip', 'unknown')

        logger.info(f"📥 Prediction request from IP: {src_ip}")

        if rf_model is None or scaler is None or feature_columns is None:
            return jsonify({'error': 'Models not loaded'}), 500

        # Map raw features to KDD format
        df = map_raw_to_kdd(raw_data)

        # Scale features (same StandardScaler used in training)
        X_scaled = scaler.transform(df.values)  # type: ignore

        # Predict
        prediction = int(rf_model.predict(X_scaled)[0])  # type: ignore
        probabilities = rf_model.predict_proba(X_scaled)[0]  # type: ignore

        # In the LabelEncoder: attack=0, normal=1
        # So probability of attack = probabilities[0]
        attack_prob: float = float(probabilities[0])
        max_prob: float = float(max(probabilities))
        
        # Round explicitly for typing
        rounded_attack_prob: float = float(f"{attack_prob:.4f}")
        rounded_max_prob: float = float(f"{max_prob:.4f}")

        # Map prediction to label
        assert label_encoder is not None
        predicted_label = label_encoder.inverse_transform([prediction])[0]
        is_attack = 1 if predicted_label == 'attack' else 0

        logger.info(f"{'🚨' if is_attack else '✅'} Prediction: {'ATTACK' if is_attack else 'NORMAL'} "
                     f"(prob: {attack_prob:.3f}) for IP: {src_ip}")

        return jsonify({
            'prediction': is_attack,
            'attack_probability': rounded_attack_prob,
            'confidence': rounded_max_prob,
            'predicted_label': predicted_label,
            'model': 'RandomForest',
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        logger.error(f"❌ Prediction error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    models_loaded = all([rf_model is not None, scaler is not None,
                         label_encoder is not None, feature_columns is not None])

    return jsonify({
        'status': 'healthy' if models_loaded else 'unhealthy',
        'models_loaded': models_loaded,
        'model_type': 'RandomForest',
        'n_features': len(feature_columns) if feature_columns else 0,
        'timestamp': datetime.utcnow().isoformat()
    })


# =============================================================================
# Startup
# =============================================================================
if __name__ == '__main__':
    print("=" * 60)
    print("  🧠 ML BACKEND — Random Forest IDS")
    print("=" * 60)

    if load_models():
        print("\n🚀 Starting ML backend on http://localhost:8080")
        app.run(host='0.0.0.0', port=8080, debug=False)
    else:
        print("\n❌ Failed to load models. Run train_rf_model.py first!")
        print("   cd ml_service && python train_rf_model.py")