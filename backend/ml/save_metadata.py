"""Save final model metadata from trained artifacts."""
import json, os, joblib, numpy as np
from datetime import datetime
from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix
import pandas as pd

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SHAP_PATH  = os.path.join(SCRIPT_DIR, "shap_data.json")
META_PATH  = os.path.join(SCRIPT_DIR, "flow_model_metadata.json")
CM_PATH    = os.path.join(SCRIPT_DIR, "flow_confusion_matrix.json")
TEST_PATH  = r"C:\Users\daniko\Desktop\CSV Files\Training and Testing Sets\UNSW_NB15_testing-set.csv"
TRAIN_PATH = r"C:\Users\daniko\Desktop\CSV Files\Training and Testing Sets\UNSW_NB15_training-set.csv"

ATTACK_MAP = {
    "Normal": "normal", "Generic": "unauthorized-access", "Exploits": "vulnerability-exploit",
    "Fuzzers": "brute-force", "DoS": "ddos", "Reconnaissance": "port-scanning",
    "Analysis": "port-scanning", "Backdoor": "malware", "Shellcode": "privilege-escalation",
    "Worms": "malware",
}

print("Loading model and data...")
with open(SHAP_PATH) as f:
    shap_data = json.load(f)

data     = joblib.load(os.path.join(SCRIPT_DIR, "flow_model.pkl"))
encoders = joblib.load(os.path.join(SCRIPT_DIR, "label_encoders.pkl"))
ensemble = data["ensemble"]
le_y     = data["le_target"]
classes  = data["classes"]
ALL_FEATURES = data["feature_names"]
CAT_FEATS    = data["categorical_features"]
NUM_FEATS    = data["numerical_features"]

def prep_df(path):
    df = pd.read_csv(path, low_memory=False)
    df["attack_cat"] = df["attack_cat"].str.strip()
    df["y"] = df["attack_cat"].map(ATTACK_MAP)
    df = df.dropna(subset=["y"])
    for col in CAT_FEATS:
        le = encoders[col]
        known = list(le.classes_)
        df[col] = df[col].astype(str).apply(lambda x: known.index(x) if x in known else len(known))
    for col in NUM_FEATS:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
    return df

df_te = prep_df(TEST_PATH)
df_tr = prep_df(TRAIN_PATH)

X_te = df_te[ALL_FEATURES].values.astype("float32")
y_te = np.array([le_y.transform([v])[0] if v in le_y.classes_ else 0 for v in df_te["y"]])

print("Predicting on test set...")
y_pred = ensemble.predict(X_te)
acc  = accuracy_score(y_te, y_pred)
f1_w = f1_score(y_te, y_pred, average="weighted", zero_division=0)
f1_m = f1_score(y_te, y_pred, average="macro",    zero_division=0)

report = classification_report(y_te, y_pred, target_names=classes, zero_division=0, output_dict=True)
cm = confusion_matrix(y_te, y_pred)

with open(CM_PATH, "w") as f:
    json.dump({"matrix": cm.tolist(), "labels": classes, "updatedAt": datetime.now().isoformat()}, f)

per_cls = {}
for cls in classes:
    if cls in report:
        per_cls[cls] = {
            "precision": round(report[cls]["precision"], 4),
            "recall":    round(report[cls]["recall"],    4),
            "f1":        round(report[cls]["f1-score"],  4),
            "support":   int(report[cls]["support"]),
        }

meta = {
    "modelType":           "XGBoost(400)+RandomForest(200) soft-voting ensemble",
    "dataset":             "UNSW-NB15 (real network intrusion dataset)",
    "trainSamples":        int(len(df_tr)),
    "testSamples":         int(len(df_te)),
    "classes":             classes,
    "accuracy":            round(float(acc), 4),
    "f1Weighted":          round(float(f1_w), 4),
    "f1Macro":             round(float(f1_m), 4),
    "featureCount":        len(ALL_FEATURES),
    "featureNames":        ALL_FEATURES,
    "topFeatures":         shap_data["globalImportance"][:20],
    "perClassTopFeatures": shap_data.get("perClassImportance", {}),
    "perClassMetrics":     per_cls,
    "attackMap":           ATTACK_MAP,
    "trainedAt":           datetime.now().isoformat(),
    "version":             "2.0",
}
with open(META_PATH, "w") as f:
    json.dump(meta, f, indent=2)

print(f"Accuracy:      {acc:.1%}")
print(f"F1 weighted:   {f1_w:.1%}")
print(f"F1 macro:      {f1_m:.1%}")
print(f"Classes:       {classes}")
print(f"Top feature:   {shap_data['globalImportance'][0]['feature']} = {shap_data['globalImportance'][0]['importance']:.4f}")
print("Metadata saved.")
