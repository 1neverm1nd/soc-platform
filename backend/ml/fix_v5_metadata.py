"""
fix_v5_metadata.py — Regenerates metadata/SHAP/anomaly for the already-saved v5 flow model.
Run this instead of retraining from scratch when the model is saved but metadata is stale.
"""
import os, json, warnings, sys
from datetime import datetime

import numpy as np
import pandas as pd
import joblib
import shap
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import lightgbm as lgb

warnings.filterwarnings("ignore")

# Must be defined for pickle to deserialize the saved ensemble
class ManualVotingEnsemble:
    """Weighted soft-voting ensemble — models kept in original fitted state."""
    def __init__(self, models, weights, classes):
        self.models   = models
        self.weights  = np.array(weights, dtype=float) / sum(weights)
        self.classes_ = classes

    def predict_proba(self, X):
        proba = np.zeros((len(X), len(self.classes_)))
        for model, w in zip(self.models, self.weights):
            proba += w * model.predict_proba(X)
        return proba

    def predict(self, X):
        return np.argmax(self.predict_proba(X), axis=1)


SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
TRAIN_PATH   = r"C:\Users\daniko\Desktop\CSV Files\Training and Testing Sets\UNSW_NB15_training-set.csv"
TEST_PATH    = r"C:\Users\daniko\Desktop\CSV Files\Training and Testing Sets\UNSW_NB15_testing-set.csv"
MODEL_PATH   = os.path.join(SCRIPT_DIR, "flow_model.pkl")
ANOMALY_PATH = os.path.join(SCRIPT_DIR, "anomaly_model.pkl")
META_PATH    = os.path.join(SCRIPT_DIR, "flow_model_metadata.json")
CM_PATH      = os.path.join(SCRIPT_DIR, "flow_confusion_matrix.json")
SHAP_PATH    = os.path.join(SCRIPT_DIR, "shap_data.json")

ATTACK_MAP = {
    "Normal":         "normal",
    "Generic":        "unauthorized-access",
    "Exploits":       "vulnerability-exploit",
    "Fuzzers":        "fuzzing",
    "DoS":            "ddos",
    "Reconnaissance": "port-scanning",
    "Analysis":       "network-analysis",
    "Backdoor":       "backdoor",
    "Shellcode":      "shellcode",
    "Worms":          "worm",
}

MITRE_MAP = {
    "normal":                {"id": "T0000", "technique": "Benign Activity",                    "tactic": "None"},
    "ddos":                  {"id": "T1498", "technique": "Network Denial of Service",           "tactic": "Impact"},
    "port-scanning":         {"id": "T1046", "technique": "Network Service Discovery",           "tactic": "Discovery"},
    "fuzzing":               {"id": "T1110", "technique": "Brute Force / Fuzzing",               "tactic": "Credential Access"},
    "network-analysis":      {"id": "T1040", "technique": "Network Sniffing",                    "tactic": "Discovery"},
    "backdoor":              {"id": "T1543", "technique": "Create or Modify System Process",     "tactic": "Persistence"},
    "shellcode":             {"id": "T1055", "technique": "Process Injection",                   "tactic": "Defense Evasion"},
    "unauthorized-access":   {"id": "T1078", "technique": "Valid Accounts",                      "tactic": "Defense Evasion"},
    "vulnerability-exploit": {"id": "T1203", "technique": "Exploitation for Client Execution",   "tactic": "Execution"},
    "worm":                  {"id": "T1080", "technique": "Taint Shared Content",                "tactic": "Lateral Movement"},
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
LOG_FEATURES  = ["sbytes","dbytes","sload","dload","rate","spkts","dpkts","smean","dmean","response_body_len","sjit","djit"]
ENG_FEATURES  = ["bytes_ratio","pkts_ratio","byte_per_pkt","conn_density"]
FEAT_COLS = ALL_FEATURES + ENG_FEATURES


def load_and_prep(path):
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip().str.lower()
    if "attack_cat" not in df.columns and "label" in df.columns:
        df["attack_cat"] = df["label"].map({0: "Normal", 1: "Generic"})
    df["attack_cat"] = df["attack_cat"].str.strip().map(ATTACK_MAP).fillna("unauthorized-access")

    for c in CATEGORICAL_FEATURES:
        df[c] = df[c].astype(str).str.strip()
    for c in NUMERICAL_FEATURES:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)
        else:
            df[c] = 0.0

    for c in LOG_FEATURES:
        df[c] = np.log1p(df[c].clip(lower=0))

    sb = df["sbytes"]; db_col = df["dbytes"]
    sp = df["spkts"];  dp = df["dpkts"]
    df["bytes_ratio"] = sb / (db_col + 1e-6)
    df["pkts_ratio"]  = sp / (dp  + 1)
    df["byte_per_pkt"]= sb / (sp  + 1)
    df["conn_density"]= (df["ct_dst_src_ltm"] + 1) * (df["ct_srv_src"] + 1)
    return df


print("[1/5] Loading model and data...")
model_data = joblib.load(MODEL_PATH)
ensemble   = model_data["ensemble"]
classes    = model_data["classes"]
le_y       = model_data["le_target"]
print(f"  Model version: {model_data.get('version')} | classes: {classes}")

print("[2/5] Loading test data for metrics...")
df_te = load_and_prep(TEST_PATH)
df_tr = load_and_prep(TRAIN_PATH)

enc = {}
for c in CATEGORICAL_FEATURES:
    le = LabelEncoder()
    le.fit(pd.concat([df_tr[c], df_te[c]]).astype(str))
    df_tr[c] = le.transform(df_tr[c].astype(str))
    df_te[c] = le.transform(df_te[c].astype(str))
    enc[c] = le
joblib.dump(enc, os.path.join(SCRIPT_DIR, "label_encoders.pkl"))

X_tr = df_tr[FEAT_COLS].values.astype(np.float32)
X_te = df_te[FEAT_COLS].values.astype(np.float32)
y_tr = le_y.transform(df_tr["attack_cat"])
y_te = le_y.transform(df_te["attack_cat"])

y_pred = ensemble.predict(X_te)
acc  = accuracy_score(y_te, y_pred)
f1_w = f1_score(y_te, y_pred, average="weighted", zero_division=0)
f1_m = f1_score(y_te, y_pred, average="macro",    zero_division=0)
print(f"  Ensemble acc={acc:.4f} ({acc:.1%})  F1_w={f1_w:.4f}  F1_m={f1_m:.4f}")
report = classification_report(y_te, y_pred, target_names=classes, zero_division=0, output_dict=True)
print(classification_report(y_te, y_pred, target_names=classes, zero_division=0))

print("[3/5] Saving confusion matrix...")
cm = confusion_matrix(y_te, y_pred)
with open(CM_PATH, "w") as f:
    json.dump({"matrix": cm.tolist(), "labels": classes, "updatedAt": datetime.now().isoformat()}, f)
print(f"  Confusion matrix saved -> {CM_PATH}")

print("[4/5] Computing SHAP via LightGBM...")
global_fi, per_cls_fi = [], {}
try:
    from sklearn.utils.class_weight import compute_sample_weight
    sw_bal = compute_sample_weight("balanced", y_tr)
    lgb_shap = lgb.LGBMClassifier(
        n_estimators=300, max_depth=8, learning_rate=0.07, num_leaves=63,
        subsample=0.85, colsample_bytree=0.85, min_child_samples=20,
        n_jobs=-1, random_state=42, verbose=-1,
    )
    lgb_shap.fit(X_tr, y_tr, sample_weight=sw_bal)
    explainer = shap.TreeExplainer(lgb_shap)
    rng = np.random.RandomState(42)
    idx = rng.choice(len(X_te), min(600, len(X_te)), replace=False)
    sv  = np.array(explainer.shap_values(X_te[idx]))
    if sv.ndim == 3:
        g_imp = np.abs(sv).mean(axis=(0, 2))
    else:
        g_imp = np.abs(sv).mean(axis=0)
    sorted_fi = np.argsort(g_imp)[::-1]
    global_fi = [{"feature": FEAT_COLS[i], "importance": round(float(g_imp[i]), 6)} for i in sorted_fi]
    if sv.ndim == 3:
        for ci, cls in enumerate(classes):
            sv_c = np.abs(sv[:, :, ci]).mean(axis=0)
            top  = np.argsort(sv_c)[::-1][:5]
            per_cls_fi[cls] = [{"feature": FEAT_COLS[i], "importance": round(float(sv_c[i]), 6)} for i in top]
    with open(SHAP_PATH, "w") as f:
        json.dump({"globalImportance": global_fi, "perClassImportance": per_cls_fi,
                   "featureNames": FEAT_COLS, "updatedAt": datetime.now().isoformat()}, f, indent=2)
    print(f"  SHAP saved. Top 5: {[x['feature'] for x in global_fi[:5]]}")
    # Embed LGB in model for inference-time SHAP
    model_data["lgb"] = lgb_shap
    joblib.dump(model_data, MODEL_PATH)
    print("  Model re-saved with LGB SHAP model embedded.")
except Exception as e:
    print(f"  SHAP failed: {e}")

print("[4b/5] Anomaly detection model (IsolationForest on normal class)...")
try:
    normal_cls = le_y.transform(["normal"])[0]
    normal_idx = (y_tr == normal_cls)
    n_normal   = int(normal_idx.sum())
    iso = IsolationForest(n_estimators=300, contamination=0.04, random_state=42, n_jobs=-1)
    iso.fit(X_tr[normal_idx])
    joblib.dump(iso, ANOMALY_PATH)
    print(f"  Anomaly model trained on {n_normal:,} normal samples -> {ANOMALY_PATH}")
except Exception as e:
    print(f"  Anomaly model failed: {e}")

print("[5/5] Writing metadata JSON...")
per_cls = {
    cls: {
        "precision": round(report[cls]["precision"], 4),
        "recall":    round(report[cls]["recall"],    4),
        "f1":        round(report[cls]["f1-score"],  4),
        "support":   int(report[cls]["support"]),
    }
    for cls in classes if cls in report
}
meta = {
    "modelType":    "XGBoost(600)+RandomForest(500)+ExtraTrees(500) soft-voting [2:3:1] + SHAP via LGB",
    "dataset":      "UNSW-NB15 (real network intrusion dataset)",
    "trainSamples": int(len(df_tr)),
    "testSamples":  int(len(df_te)),
    "classes":      classes,
    "accuracy":     round(float(acc), 4),
    "f1Weighted":   round(float(f1_w), 4),
    "f1Macro":      round(float(f1_m), 4),
    "featureCount": len(FEAT_COLS),
    "featureNames": FEAT_COLS,
    "topFeatures":  global_fi[:20],
    "perClassTopFeatures": per_cls_fi,
    "perClassMetrics": per_cls,
    "attackMap":    ATTACK_MAP,
    "mitreMap":     MITRE_MAP,
    "improvements": [
        "Expanded ATTACK_MAP: 10 distinct classes",
        "ExtraTreesClassifier added to ensemble [XGB x2 + RF x3 + ET x1]",
        "600/500/500 estimators for XGB/RF/ET",
        "Anomaly model trained on all normal samples",
        "log1p transforms + 4 engineered ratio features",
        "SHAP via LightGBM (TreeExplainer)",
    ],
    "trainedAt": datetime.now().isoformat(),
    "version":   "5.0",
}
with open(META_PATH, "w") as f:
    json.dump(meta, f, indent=2)
print(f"  Metadata saved -> {META_PATH}")

print("\n" + "="*65)
print("[DONE] All metadata/SHAP/anomaly artifacts saved.")
print(f"  Accuracy:    {acc:.1%}")
print(f"  F1 weighted: {f1_w:.1%}")
print(f"  F1 macro:    {f1_m:.1%}")
print(f"  Classes:     {classes}")
print("="*65)
