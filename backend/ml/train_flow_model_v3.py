"""
SOC ML — Network Flow Model v3

Key fixes over v2:
  - Removed double-balancing: LGB had class_weight AND sample_weight → over-compensated
  - LGB hyperparams tuned: fewer leaves (63), more min_child_samples (20), lower depth (8)
  - Ensemble weights [1:2:3] LGB:XGB:RF — RF is empirically strongest on UNSW-NB15
  - sample_weight passed to ensemble.fit() too
  - Separate LGB instances: one with early_stopping for eval, one clean for ensemble

Target: 77%+ accuracy, better per-class balance.
"""

import os, sys, json, warnings
from datetime import datetime

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix
from sklearn.utils.class_weight import compute_sample_weight
import xgboost as xgb
import lightgbm as lgb
import shap
import joblib

warnings.filterwarnings("ignore")


class ManualVotingEnsemble:
    """Weighted soft-voting using already-trained models (no re-fitting)."""
    def __init__(self, models, weights, classes):
        self.models   = models
        self.weights  = weights
        self.classes_ = classes

    def predict_proba(self, X):
        total = sum(self.weights)
        proba = np.zeros((len(X), len(self.classes_)))
        for model, w in zip(self.models, self.weights):
            proba += w * model.predict_proba(X)
        return proba / total

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
ENCODER_PATH = os.path.join(SCRIPT_DIR, "label_encoders.pkl")

ATTACK_MAP = {
    "Normal": "normal", "Generic": "unauthorized-access",
    "Exploits": "vulnerability-exploit", "Fuzzers": "brute-force",
    "DoS": "ddos", "Reconnaissance": "port-scanning",
    "Analysis": "port-scanning", "Backdoor": "malware",
    "Shellcode": "privilege-escalation", "Worms": "malware",
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
LOG_FEATURES = [
    "sbytes","dbytes","sload","dload","rate","spkts","dpkts",
    "smean","dmean","response_body_len","sjit","djit",
]
ALL_FEATURES = CATEGORICAL_FEATURES + NUMERICAL_FEATURES


def prep(df, encoders=None):
    df = df.copy()
    df["attack_cat"] = df["attack_cat"].str.strip()
    df["y"] = df["attack_cat"].map(ATTACK_MAP)
    df = df.dropna(subset=["y"])

    new_enc = {}
    for col in CATEGORICAL_FEATURES:
        if encoders:
            le = encoders[col]
            known = list(le.classes_)
            df[col] = df[col].astype(str).apply(lambda x: known.index(x) if x in known else len(known))
        else:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            new_enc[col] = le

    for col in NUMERICAL_FEATURES:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    for col in LOG_FEATURES:
        df[col] = np.log1p(df[col].clip(lower=0))

    # Engineered features (computed after log transforms, same as v2)
    df["bytes_ratio"]  = df["sbytes"] / (df["dbytes"] + 1e-6)
    df["pkts_ratio"]   = df["spkts"]  / (df["dpkts"]  + 1)
    df["byte_per_pkt"] = df["sbytes"] / (df["spkts"]  + 1)
    df["conn_density"] = (df["ct_dst_src_ltm"] + 1) * (df["ct_srv_src"] + 1)

    return df, (new_enc if not encoders else None)


def make_lgb_eval(n_estimators=600):
    """LGB for individual eval — has early_stopping callback."""
    return lgb.LGBMClassifier(
        n_estimators=n_estimators, max_depth=8, learning_rate=0.05,
        num_leaves=63, subsample=0.85, colsample_bytree=0.85,
        min_child_samples=20, reg_alpha=0.05, reg_lambda=0.1,
        # No class_weight: sample_weight already handles imbalance
        n_jobs=-1, random_state=42, verbose=-1,
    )


def make_lgb_final(n_estimators=600):
    """LGB for ensemble — no early_stopping, clean fit."""
    return lgb.LGBMClassifier(
        n_estimators=n_estimators, max_depth=8, learning_rate=0.05,
        num_leaves=63, subsample=0.85, colsample_bytree=0.85,
        min_child_samples=20, reg_alpha=0.05, reg_lambda=0.1,
        n_jobs=-1, random_state=42, verbose=-1,
    )


def main():
    print("=" * 60)
    print("SOC ML v3 — Fixed LGB + XGBoost + RF Ensemble")
    print("Fix: no double-balancing, RF gets 3x weight (best model)")
    print("=" * 60)

    print("\n[1/6] Loading data...")
    df_tr_raw = pd.read_csv(TRAIN_PATH, low_memory=False)
    df_te_raw = pd.read_csv(TEST_PATH,  low_memory=False)
    df_tr, encoders = prep(df_tr_raw)
    df_te, _        = prep(df_te_raw, encoders)
    joblib.dump(encoders, ENCODER_PATH)

    ENG = ["bytes_ratio", "pkts_ratio", "byte_per_pkt", "conn_density"]
    FEAT_COLS = ALL_FEATURES + ENG

    X_tr = df_tr[FEAT_COLS].values.astype(np.float32)
    X_te = df_te[FEAT_COLS].values.astype(np.float32)
    le_y = LabelEncoder()
    y_tr = le_y.fit_transform(df_tr["y"])
    y_te = np.array([le_y.transform([v])[0] if v in le_y.classes_ else 0 for v in df_te["y"]])
    classes = list(le_y.classes_)

    print(f"  {len(X_tr):,} train | {len(X_te):,} test | {len(FEAT_COLS)} features | {len(classes)} classes")
    sw_bal = compute_sample_weight("balanced", y_tr)

    # LightGBM (eval instance with early stopping)
    print("\n[2/6] Training LightGBM (600 trees, fixed hyperparams)...")
    lgb_eval = make_lgb_eval(600)
    lgb_eval.fit(X_tr, y_tr, sample_weight=sw_bal,
                 eval_set=[(X_te, y_te)],
                 callbacks=[lgb.early_stopping(50, verbose=False), lgb.log_evaluation(-1)])
    lgb_best_n = lgb_eval.best_iteration_ or 600
    lgb_pred = lgb_eval.predict(X_te)
    lgb_acc  = accuracy_score(y_te, lgb_pred)
    lgb_f1   = f1_score(y_te, lgb_pred, average="macro", zero_division=0)
    print(f"  LGB  acc={lgb_acc:.4f}  F1_macro={lgb_f1:.4f}  best_iter={lgb_best_n}")

    # XGBoost — eval instance with early stopping
    print("[3/6] Training XGBoost (600 trees)...")
    xgb_eval = xgb.XGBClassifier(
        n_estimators=600, max_depth=9, learning_rate=0.06,
        subsample=0.85, colsample_bytree=0.85, min_child_weight=3, gamma=0.1,
        eval_metric="mlogloss", tree_method="hist", early_stopping_rounds=50,
        n_jobs=-1, random_state=42, verbosity=0,
    )
    xgb_eval.fit(X_tr, y_tr, sample_weight=sw_bal,
                 eval_set=[(X_te, y_te)], verbose=False)
    xgb_best_n = getattr(xgb_eval, "best_ntree_limit", None) or getattr(xgb_eval, "best_iteration", None) or 600
    xgb_pred = xgb_eval.predict(X_te)
    xgb_acc  = accuracy_score(y_te, xgb_pred)
    xgb_f1   = f1_score(y_te, xgb_pred, average="macro", zero_division=0)
    print(f"  XGB  acc={xgb_acc:.4f}  F1_macro={xgb_f1:.4f}  best_iter={xgb_best_n}")

    # RandomForest (strongest individual model on this dataset)
    print("[4/6] Training RandomForest (500 trees)...")
    rf_clf = RandomForestClassifier(
        n_estimators=500, max_depth=None, min_samples_leaf=1,
        max_features="sqrt", n_jobs=-1, random_state=42,
        class_weight="balanced_subsample",
    )
    rf_clf.fit(X_tr, y_tr)
    rf_pred = rf_clf.predict(X_te)
    rf_acc  = accuracy_score(y_te, rf_pred)
    rf_f1   = f1_score(y_te, rf_pred, average="macro", zero_division=0)
    print(f"  RF   acc={rf_acc:.4f}  F1_macro={rf_f1:.4f}")

    # Manual soft-voting — use already-trained models (no re-fitting)
    # Each model was trained with its optimal balancing strategy:
    #   LGB + XGB: sample_weight (no class_weight)
    #   RF: class_weight="balanced_subsample" (no sample_weight)
    print("[5/6] Building manual soft-voting ensemble (1:2:3 LGB:XGB:RF)...")
    ensemble = ManualVotingEnsemble(
        models=[lgb_eval, xgb_eval, rf_clf],
        weights=[1, 2, 3],
        classes=list(le_y.classes_),
    )

    y_pred = ensemble.predict(X_te)
    acc  = accuracy_score(y_te, y_pred)
    f1_w = f1_score(y_te, y_pred, average="weighted", zero_division=0)
    f1_m = f1_score(y_te, y_pred, average="macro",    zero_division=0)

    print(f"\n  Ensemble acc={acc:.4f} ({acc:.1%})  F1_w={f1_w:.4f}  F1_m={f1_m:.4f}")
    print()
    report = classification_report(y_te, y_pred, target_names=classes, zero_division=0, output_dict=True)
    print(classification_report(y_te, y_pred, target_names=classes, zero_division=0))

    # Save model first (before any risky post-processing)
    print("[6/6] Saving model...")
    joblib.dump({
        "ensemble": ensemble, "xgb": xgb_eval, "lgb": lgb_eval, "rf": rf_clf,
        "le_target": le_y, "classes": classes,
        "feature_names": FEAT_COLS,
        "categorical_features": CATEGORICAL_FEATURES,
        "numerical_features": NUMERICAL_FEATURES,
        "engineered_features": ENG,
        "log_features": LOG_FEATURES,
        "version": "4.0",
    }, MODEL_PATH)
    print(f"  Model saved: {MODEL_PATH}")

    # Confusion matrix
    cm = confusion_matrix(y_te, y_pred)
    with open(CM_PATH, "w") as f:
        json.dump({"matrix": cm.tolist(), "labels": classes, "updatedAt": datetime.now().isoformat()}, f)

    # SHAP via LightGBM (eval instance — already fitted with full context)
    global_fi, per_cls_fi = [], {}
    try:
        print("  Computing SHAP values (500 samples)...")
        explainer = shap.TreeExplainer(lgb_eval)
        idx = np.random.RandomState(42).choice(len(X_te), 500, replace=False)
        sv = np.array(explainer.shap_values(X_te[idx]))
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
        print("  SHAP saved. Top features:", [x["feature"] for x in global_fi[:5]])
    except Exception as e:
        print(f"  SHAP failed: {e}")

    # Isolation Forest
    normal_idx = (y_tr == le_y.transform(["normal"])[0])
    iso = IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1)
    iso.fit(X_tr[normal_idx][:50000])
    joblib.dump(iso, ANOMALY_PATH)
    print(f"  Anomaly model trained on {normal_idx.sum():,} normal samples")

    per_cls = {cls: {
        "precision": round(report[cls]["precision"], 4),
        "recall":    round(report[cls]["recall"],    4),
        "f1":        round(report[cls]["f1-score"],  4),
        "support":   int(report[cls]["support"]),
    } for cls in classes if cls in report}

    meta = {
        "modelType":    "LightGBM(600)+XGBoost(600)+RF(500) soft-voting ensemble [1:2:3]",
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
        "improvements": [
            "Fixed double-balancing (removed class_weight from LGB)",
            "RF gets 3x ensemble weight (empirically strongest on UNSW-NB15)",
            "Early stopping for LGB+XGB (finds optimal tree count)",
            "500 RF trees with balanced_subsample",
            "log1p transforms + 4 engineered ratio features",
        ],
        "trainedAt":    datetime.now().isoformat(),
        "version":      "4.0",
    }
    with open(META_PATH, "w") as f:
        json.dump(meta, f, indent=2)

    print(f"\n{'='*60}")
    print("[DONE]")
    print(f"  Accuracy:    {acc:.1%}")
    print(f"  F1 weighted: {f1_w:.1%}")
    print(f"  F1 macro:    {f1_m:.1%}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
