"""Compute SHAP values and save anomaly model (run after training)."""
import joblib, json, numpy as np, os, shap, pandas as pd
from datetime import datetime
from sklearn.ensemble import IsolationForest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH  = os.path.join(SCRIPT_DIR, "flow_model.pkl")
ANOMALY_PATH = os.path.join(SCRIPT_DIR, "anomaly_model.pkl")
META_PATH   = os.path.join(SCRIPT_DIR, "flow_model_metadata.json")
SHAP_PATH   = os.path.join(SCRIPT_DIR, "shap_data.json")
CM_PATH     = os.path.join(SCRIPT_DIR, "flow_confusion_matrix.json")
TEST_PATH   = r"C:\Users\daniko\Desktop\CSV Files\Training and Testing Sets\UNSW_NB15_testing-set.csv"
TRAIN_PATH  = r"C:\Users\daniko\Desktop\CSV Files\Training and Testing Sets\UNSW_NB15_training-set.csv"

ATTACK_MAP = {
    "Normal":"normal","Generic":"unauthorized-access","Exploits":"vulnerability-exploit",
    "Fuzzers":"brute-force","DoS":"ddos","Reconnaissance":"port-scanning",
    "Analysis":"port-scanning","Backdoor":"malware","Shellcode":"privilege-escalation","Worms":"malware"
}

def load_df(path, encoders, ALL_FEATURES, CATEGORICAL_FEATURES, NUMERICAL_FEATURES):
    df = pd.read_csv(path, low_memory=False)
    df["attack_cat"] = df["attack_cat"].str.strip()
    df["y"] = df["attack_cat"].map(ATTACK_MAP)
    df = df.dropna(subset=["y"])
    for col in CATEGORICAL_FEATURES:
        le = encoders[col]
        classes_list = list(le.classes_)
        df[col] = df[col].astype(str).apply(
            lambda x: classes_list.index(x) if x in classes_list else len(classes_list)
        )
    for col in NUMERICAL_FEATURES:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
    return df


print("Loading saved model...")
data = joblib.load(MODEL_PATH)
xgb_clf       = data["xgb"]
ensemble      = data["ensemble"]
le_target     = data["le_target"]
classes       = data["classes"]
ALL_FEATURES  = data["feature_names"]
CAT_FEATS     = data["categorical_features"]
NUM_FEATS     = data["numerical_features"]

encoders = joblib.load(os.path.join(SCRIPT_DIR, "label_encoders.pkl"))

print("Loading test data...")
df_test  = load_df(TEST_PATH,  encoders, ALL_FEATURES, CAT_FEATS, NUM_FEATS)
df_train = load_df(TRAIN_PATH, encoders, ALL_FEATURES, CAT_FEATS, NUM_FEATS)

X_test  = df_test[ALL_FEATURES].values.astype("float32")
X_train = df_train[ALL_FEATURES].values.astype("float32")
y_test  = le_target.transform(df_test["y"])

# --- SHAP ---
print("Computing SHAP values (sample=800)...")
explainer = shap.TreeExplainer(xgb_clf)
idx = np.random.RandomState(42).choice(len(X_test), 800, replace=False)
shap_values = explainer.shap_values(X_test[idx])
sv = np.array(shap_values)
print(f"  SHAP array shape: {sv.shape}")

if sv.ndim == 3:
    mean_shap = np.abs(sv).mean(axis=(0, 2))
elif sv.ndim == 2:
    mean_shap = np.abs(sv).mean(axis=0)
else:
    mean_shap = np.abs(sv).ravel()

sorted_idx = np.argsort(mean_shap)[::-1]
feature_importance = [
    {"feature": ALL_FEATURES[i], "importance": round(float(mean_shap[i]), 6)}
    for i in sorted_idx
]

per_class_shap = {}
if sv.ndim == 3:
    for ci, cls in enumerate(classes):
        sv_cls = np.abs(sv[:, :, ci]).mean(axis=0)
        top_idx = np.argsort(sv_cls)[::-1][:5]
        per_class_shap[cls] = [
            {"feature": ALL_FEATURES[i], "importance": round(float(sv_cls[i]), 6)}
            for i in top_idx
        ]

shap_data = {
    "globalImportance": feature_importance,
    "perClassImportance": per_class_shap,
    "featureNames": ALL_FEATURES,
    "updatedAt": datetime.now().isoformat(),
}
with open(SHAP_PATH, "w") as f:
    json.dump(shap_data, f, indent=2)

print("\n  Top 15 features by SHAP importance:")
for fi in feature_importance[:15]:
    bar = "#" * int(fi["importance"] / feature_importance[0]["importance"] * 20)
    print(f"    {fi['feature']:<25} {bar:<20} {fi['importance']:.4f}")

# --- Anomaly Detector ---
print("\nTraining Isolation Forest anomaly detector...")
normal_label = le_target.transform(["normal"])[0]
X_normal = X_train[le_target.transform(df_train["y"]) == normal_label]
iso = IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1)
iso.fit(X_normal[:50000])
joblib.dump(iso, ANOMALY_PATH)
print(f"  Trained on {min(len(X_normal), 50000):,} normal samples")

# --- Update metadata with SHAP ---
print("\nUpdating metadata with SHAP feature importance...")
meta = {}
if os.path.exists(META_PATH):
    with open(META_PATH, "r") as f:
        meta = json.load(f)
meta["topFeatures"] = feature_importance[:20]
meta["perClassTopFeatures"] = per_class_shap
meta["shapUpdatedAt"] = datetime.now().isoformat()
with open(META_PATH, "w") as f:
    json.dump(meta, f, indent=2)

print("\n[DONE] SHAP + anomaly detector saved.")
print(f"  shap_data.json: {SHAP_PATH}")
print(f"  anomaly_model:  {ANOMALY_PATH}")
