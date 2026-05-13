"""
Train SOC Network Flow ML Model on UNSW-NB15 dataset.

Architecture:
  - XGBoost (400 trees, primary classifier)
  - RandomForest (200 trees, ensemble member)
  - Soft-voting ensemble (3:1 XGB:RF weights)
  - SHAP explainer for feature importance
  - Isolation Forest anomaly detector (zero-day)

Outputs:
  flow_model.pkl              trained ensemble + metadata
  anomaly_model.pkl           Isolation Forest
  flow_model_metadata.json    accuracy, F1, per-class metrics
  flow_confusion_matrix.json  confusion matrix
  shap_data.json              SHAP feature importance
  label_encoders.pkl          categorical feature encoders
"""

import os, sys, json, warnings
from datetime import datetime

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, VotingClassifier, IsolationForest
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score, f1_score, classification_report, confusion_matrix
)
from sklearn.utils.class_weight import compute_sample_weight
import xgboost as xgb
import shap
import joblib

warnings.filterwarnings("ignore")

SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
TRAIN_PATH   = r"C:\Users\daniko\Desktop\CSV Files\Training and Testing Sets\UNSW_NB15_training-set.csv"
TEST_PATH    = r"C:\Users\daniko\Desktop\CSV Files\Training and Testing Sets\UNSW_NB15_testing-set.csv"
MODEL_PATH   = os.path.join(SCRIPT_DIR, "flow_model.pkl")
ANOMALY_PATH = os.path.join(SCRIPT_DIR, "anomaly_model.pkl")
META_PATH    = os.path.join(SCRIPT_DIR, "flow_model_metadata.json")
CM_PATH      = os.path.join(SCRIPT_DIR, "flow_confusion_matrix.json")
SHAP_PATH    = os.path.join(SCRIPT_DIR, "shap_data.json")
ENCODER_PATH = os.path.join(SCRIPT_DIR, "label_encoders.pkl")

ATTACK_MAP = {
    "Normal":         "normal",
    "Generic":        "unauthorized-access",
    "Exploits":       "vulnerability-exploit",
    "Fuzzers":        "brute-force",
    "DoS":            "ddos",
    "Reconnaissance": "port-scanning",
    "Analysis":       "port-scanning",
    "Backdoor":       "malware",
    "Shellcode":      "privilege-escalation",
    "Worms":          "malware",
}

CATEGORICAL_FEATURES = ["proto", "service", "state"]
NUMERICAL_FEATURES = [
    "dur","spkts","dpkts","sbytes","dbytes","rate","sttl","dttl",
    "sload","dload","sloss","dloss","sinpkt","dinpkt","sjit","djit",
    "swin","stcpb","dtcpb","dwin","tcprtt","synack","ackdat",
    "smean","dmean","trans_depth","response_body_len",
    "ct_srv_src","ct_state_ttl","ct_dst_ltm","ct_src_dport_ltm",
    "ct_dst_sport_ltm","ct_dst_src_ltm","is_ftp_login","ct_ftp_cmd",
    "ct_flw_http_mthd","ct_src_ltm","ct_srv_dst","is_sm_ips_ports",
]
ALL_FEATURES = CATEGORICAL_FEATURES + NUMERICAL_FEATURES


def load_and_encode(train_path, test_path):
    df_tr = pd.read_csv(train_path, low_memory=False)
    df_te = pd.read_csv(test_path,  low_memory=False)
    for df in (df_tr, df_te):
        df["attack_cat"] = df["attack_cat"].str.strip()
        df["y"] = df["attack_cat"].map(ATTACK_MAP)

    df_tr = df_tr.dropna(subset=["y"])
    df_te = df_te.dropna(subset=["y"])

    encoders = {}
    for col in CATEGORICAL_FEATURES:
        le = LabelEncoder()
        df_tr[col] = le.fit_transform(df_tr[col].astype(str))
        known = list(le.classes_)
        df_te[col] = df_te[col].astype(str).apply(
            lambda x: known.index(x) if x in known else len(known)
        )
        encoders[col] = le

    for col in NUMERICAL_FEATURES:
        df_tr[col] = pd.to_numeric(df_tr[col], errors="coerce").fillna(0)
        df_te[col] = pd.to_numeric(df_te[col], errors="coerce").fillna(0)

    return df_tr, df_te, encoders


def main():
    print("=" * 60)
    print("SOC ML — Network Flow Model Training")
    print("Dataset: UNSW-NB15 (257K+ real network flows)")
    print("=" * 60)

    # 1. Load & encode
    print("\n[1/6] Loading and encoding data...")
    df_tr, df_te, encoders = load_and_encode(TRAIN_PATH, TEST_PATH)
    joblib.dump(encoders, ENCODER_PATH)

    X_tr = df_tr[ALL_FEATURES].values.astype(np.float32)
    X_te = df_te[ALL_FEATURES].values.astype(np.float32)

    le_y = LabelEncoder()
    y_tr = le_y.fit_transform(df_tr["y"])
    # map any unseen test classes to 0
    y_te = np.array([
        le_y.transform([v])[0] if v in le_y.classes_ else 0
        for v in df_te["y"]
    ])
    classes = list(le_y.classes_)

    print(f"  Train: {len(X_tr):,} | Test: {len(X_te):,} | Classes: {len(classes)}")
    print("  Distribution:")
    for cls, cnt in df_tr["y"].value_counts().items():
        print(f"    {cls:<28} {cnt:>6,}  ({cnt/len(df_tr)*100:.1f}%)")

    sw = compute_sample_weight("balanced", y_tr)

    # 2. Train XGBoost
    print("\n[2/6] Training XGBoost (400 trees, depth 8)...")
    xgb_clf = xgb.XGBClassifier(
        n_estimators=400, max_depth=8, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.8, min_child_weight=3,
        eval_metric="mlogloss", tree_method="hist",
        n_jobs=-1, random_state=42, verbosity=0,
    )
    xgb_clf.fit(X_tr, y_tr, sample_weight=sw,
                eval_set=[(X_te, y_te)], verbose=False)

    # 3. Train RandomForest
    print("[3/6] Training RandomForest (200 trees, depth 20)...")
    rf_clf = RandomForestClassifier(
        n_estimators=200, max_depth=20, min_samples_split=5,
        min_samples_leaf=2, n_jobs=-1, random_state=42, class_weight="balanced",
    )
    rf_clf.fit(X_tr, y_tr)

    # 4. Ensemble & evaluate
    print("[4/6] Building soft-voting ensemble and evaluating...")
    ensemble = VotingClassifier(
        estimators=[("xgb", xgb_clf), ("rf", rf_clf)],
        voting="soft", weights=[3, 1],
    )
    ensemble.fit(X_tr, y_tr)

    y_pred  = ensemble.predict(X_te)
    y_proba = ensemble.predict_proba(X_te)
    acc  = accuracy_score(y_te, y_pred)
    f1_w = f1_score(y_te, y_pred, average="weighted", zero_division=0)
    f1_m = f1_score(y_te, y_pred, average="macro",    zero_division=0)

    print(f"\n  Accuracy:      {acc:.4f}  ({acc:.1%})")
    print(f"  F1 weighted:   {f1_w:.4f}")
    print(f"  F1 macro:      {f1_m:.4f}")
    print()
    report = classification_report(y_te, y_pred, target_names=classes,
                                   zero_division=0, output_dict=True)
    print(classification_report(y_te, y_pred, target_names=classes, zero_division=0))

    # confusion matrix
    cm = confusion_matrix(y_te, y_pred)
    with open(CM_PATH, "w") as f:
        json.dump({"matrix": cm.tolist(), "labels": classes,
                   "updatedAt": datetime.now().isoformat()}, f)

    # 5. SAVE MODEL (before SHAP so failures don't lose trained model)
    print("[5/6] Saving model...")
    joblib.dump({
        "ensemble": ensemble,
        "xgb":      xgb_clf,
        "rf":       rf_clf,
        "le_target":   le_y,
        "classes":     classes,
        "feature_names":        ALL_FEATURES,
        "categorical_features": CATEGORICAL_FEATURES,
        "numerical_features":   NUMERICAL_FEATURES,
    }, MODEL_PATH)
    print(f"  Saved: {MODEL_PATH}")

    # 6. SHAP + Anomaly detector
    print("[6/6] SHAP explainability + Isolation Forest...")

    explainer   = shap.TreeExplainer(xgb_clf)
    rng         = np.random.RandomState(42)
    idx         = rng.choice(len(X_te), min(800, len(X_te)), replace=False)
    shap_vals   = np.array(explainer.shap_values(X_te[idx]))
    print(f"  SHAP shape: {shap_vals.shape}")

    # mean |SHAP| globally
    if shap_vals.ndim == 3:
        g_imp = np.abs(shap_vals).mean(axis=(0, 2))
    else:
        g_imp = np.abs(shap_vals).mean(axis=0)

    sorted_fi = np.argsort(g_imp)[::-1]
    global_fi = [
        {"feature": ALL_FEATURES[i], "importance": round(float(g_imp[i]), 6)}
        for i in sorted_fi
    ]

    # per-class top-5
    per_cls_fi = {}
    if shap_vals.ndim == 3:
        for ci, cls in enumerate(classes):
            sv_c = np.abs(shap_vals[:, :, ci]).mean(axis=0)
            top  = np.argsort(sv_c)[::-1][:5]
            per_cls_fi[cls] = [
                {"feature": ALL_FEATURES[i], "importance": round(float(sv_c[i]), 6)}
                for i in top
            ]

    with open(SHAP_PATH, "w") as f:
        json.dump({"globalImportance": global_fi, "perClassImportance": per_cls_fi,
                   "featureNames": ALL_FEATURES, "updatedAt": datetime.now().isoformat()}, f, indent=2)

    print("\n  Top 15 features (SHAP):")
    max_imp = global_fi[0]["importance"]
    for fi in global_fi[:15]:
        bar = "#" * int(fi["importance"] / max_imp * 20)
        print(f"    {fi['feature']:<25} {bar:<20} {fi['importance']:.4f}")

    # Isolation Forest on normal traffic
    normal_idx = (y_tr == le_y.transform(["normal"])[0])
    X_norm = X_tr[normal_idx][:50000]
    iso = IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1)
    iso.fit(X_norm)
    joblib.dump(iso, ANOMALY_PATH)
    print(f"\n  Isolation Forest trained on {len(X_norm):,} normal samples")

    # Metadata
    per_cls_metrics = {}
    for cls in classes:
        if cls in report:
            per_cls_metrics[cls] = {
                "precision": round(report[cls]["precision"], 4),
                "recall":    round(report[cls]["recall"],    4),
                "f1":        round(report[cls]["f1-score"],  4),
                "support":   int(report[cls]["support"]),
            }

    meta = {
        "modelType":         "XGBoost(400)+RandomForest(200) soft-voting ensemble",
        "dataset":           "UNSW-NB15",
        "trainSamples":      int(len(df_tr)),
        "testSamples":       int(len(df_te)),
        "classes":           classes,
        "accuracy":          round(float(acc), 4),
        "f1Weighted":        round(float(f1_w), 4),
        "f1Macro":           round(float(f1_m), 4),
        "featureCount":      len(ALL_FEATURES),
        "featureNames":      ALL_FEATURES,
        "topFeatures":       global_fi[:20],
        "perClassTopFeatures": per_cls_fi,
        "perClassMetrics":   per_cls_metrics,
        "attackMap":         ATTACK_MAP,
        "trainedAt":         datetime.now().isoformat(),
        "version":           "2.0",
    }
    with open(META_PATH, "w") as f:
        json.dump(meta, f, indent=2)

    print(f"\n{'='*60}")
    print("[DONE] All models trained and saved!")
    print(f"  Accuracy:      {acc:.1%}")
    print(f"  F1 (weighted): {f1_w:.1%}")
    print(f"  F1 (macro):    {f1_m:.1%}")
    print(f"  flow_model.pkl, anomaly_model.pkl, shap_data.json")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
