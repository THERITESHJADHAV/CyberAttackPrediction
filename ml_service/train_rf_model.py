"""
RANDOM FOREST MODEL TRAINING SCRIPT
====================================
Replicates the IDS.ipynb notebook pipeline to train a Random Forest
classifier on the KDD dataset and save all artifacts needed by the backend.

Usage:
    cd ml_service
    python train_rf_model.py
"""

import os
import sys
import joblib  # type: ignore
import numpy as np  # type: ignore
import pandas as pd  # type: ignore
from sklearn.preprocessing import StandardScaler, LabelEncoder  # type: ignore
from sklearn.ensemble import RandomForestClassifier  # type: ignore
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report  # type: ignore

# =============================================================================
# Configuration
# =============================================================================
TRAIN_CSV = os.path.join(os.path.dirname(__file__), '..', 'kdd_train.csv')
TEST_CSV  = os.path.join(os.path.dirname(__file__), '..', 'kdd_test.csv')
ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), 'rf_artifacts')

# =============================================================================
# Step 1: Load Data
# =============================================================================
print("=" * 60)
print("  RANDOM FOREST IDS MODEL — TRAINING PIPELINE")
print("=" * 60)

print("\n📂 Loading datasets...")
train_df = pd.read_csv(TRAIN_CSV)
test_df  = pd.read_csv(TEST_CSV)
print(f"   Train shape: {train_df.shape}")
print(f"   Test  shape: {test_df.shape}")

# =============================================================================
# Step 2: Binary Label Mapping (exactly like the notebook)
# =============================================================================
print("\n🏷️  Mapping labels to binary (normal / attack)...")
train_df['label'] = train_df['label'].apply(lambda x: 'normal' if x == 'normal' else 'attack')
test_df['label']  = test_df['label'].apply(lambda x: 'normal' if x == 'normal' else 'attack')

print(f"   Train label distribution:\n{train_df['label'].value_counts().to_string()}")
print(f"   Test  label distribution:\n{test_df['label'].value_counts().to_string()}")

# =============================================================================
# Step 3: Drop NaN rows and difficulty_level
# =============================================================================
print("\n🧹 Cleaning data...")
train_df = train_df.dropna()
test_df  = test_df.dropna()

if 'difficulty_level' in train_df.columns:
    train_df = train_df.drop('difficulty_level', axis=1)
    test_df  = test_df.drop('difficulty_level', axis=1)
    print("   Dropped 'difficulty_level' column")

print(f"   Train shape after cleaning: {train_df.shape}")
print(f"   Test  shape after cleaning: {test_df.shape}")

# =============================================================================
# Step 4: Separate features and labels
# =============================================================================
y_train = train_df['label']
y_test  = test_df['label']

X_train = train_df.drop('label', axis=1)
X_test  = test_df.drop('label', axis=1)

# =============================================================================
# Step 5: One-Hot Encode categorical columns (exactly like notebook)
# =============================================================================
print("\n🔢 One-hot encoding categorical features...")
X_train = pd.get_dummies(X_train)
X_test  = pd.get_dummies(X_test)

# Align columns (train is the reference)
X_train, X_test = X_train.align(X_test, join='left', axis=1)
X_test = X_test.fillna(0)

feature_columns = list(X_train.columns)
print(f"   Total features after encoding: {len(feature_columns)}")

# =============================================================================
# Step 6: StandardScaler (exactly like notebook)
# =============================================================================
print("\n📏 Scaling features with StandardScaler...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled  = scaler.transform(X_test)

# =============================================================================
# Step 7: LabelEncoder (exactly like notebook)
# =============================================================================
print("\n🏷️  Encoding labels (attack=0, normal=1)...")
le = LabelEncoder()
y_train_enc = le.fit_transform(y_train)
y_test_enc  = le.transform(y_test)
print(f"   Classes: {list(le.classes_)}")
print(f"   Mapping: {dict(zip(le.classes_, le.transform(le.classes_)))}")

# =============================================================================
# Step 8: Train Random Forest (exactly like notebook)
# =============================================================================
print("\n🌲 Training Random Forest Classifier...")
print("   n_estimators=100, random_state=42, n_jobs=-1")

rf = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)
rf.fit(X_train_scaled, y_train_enc)
print("   ✅ Training complete!")

# =============================================================================
# Step 9: Evaluate
# =============================================================================
print("\n📊 Evaluating on test set...")
y_pred = rf.predict(X_test_scaled)

acc  = accuracy_score(y_test_enc, y_pred)
prec = precision_score(y_test_enc, y_pred, average='weighted')
rec  = recall_score(y_test_enc, y_pred, average='weighted')
f1   = f1_score(y_test_enc, y_pred, average='weighted')

print(f"\n{'='*40}")
print(f"   Accuracy  : {acc:.4f}")
print(f"   Precision : {prec:.4f}")
print(f"   Recall    : {rec:.4f}")
print(f"   F1-Score  : {f1:.4f}")
print(f"{'='*40}")

print("\n📋 Classification Report:")
print(classification_report(y_test_enc, y_pred, target_names=['Attack', 'Normal']))

# =============================================================================
# Step 10: Save Artifacts
# =============================================================================
print("\n💾 Saving model artifacts...")
os.makedirs(ARTIFACTS_DIR, exist_ok=True)

joblib.dump(rf, os.path.join(ARTIFACTS_DIR, 'rf_model.pkl'))
print(f"   ✅ Saved rf_model.pkl")

joblib.dump(scaler, os.path.join(ARTIFACTS_DIR, 'scaler.pkl'))
print(f"   ✅ Saved scaler.pkl")

joblib.dump(le, os.path.join(ARTIFACTS_DIR, 'label_encoder.pkl'))
print(f"   ✅ Saved label_encoder.pkl")

joblib.dump(feature_columns, os.path.join(ARTIFACTS_DIR, 'feature_columns.pkl'))
print(f"   ✅ Saved feature_columns.pkl ({len(feature_columns)} features)")

# Also save a human-readable feature list
with open(os.path.join(ARTIFACTS_DIR, 'feature_columns.txt'), 'w') as f:
    for col in feature_columns:
        f.write(col + '\n')

print(f"\n🎉 All artifacts saved to: {os.path.abspath(ARTIFACTS_DIR)}")
print("   You can now start the ML backend with: python ml_ec2_service.py")
