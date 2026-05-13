"""
SOC Platform ML Inference Engine — v3.0
Supports three modes:
  1. TEXT mode   — raw log text → TF-IDF text classifier
  2. FLOW mode   — JSON network flow features → LightGBM+XGBoost+RF ensemble
  3. HYBRID mode — both present → weighted ensemble vote (flow 70%, text 30%)

v3 features: log1p transforms + 4 engineered ratio features, no SMOTE.

Input  (stdin): raw log text  OR  JSON with optional 'features' key
Output (stdout): JSON prediction with SHAP explanation

JSON input format for FLOW mode:
{
  "text": "optional raw log",
  "features": {
    "dur": 0.5, "proto": "tcp", "service": "http", "state": "FIN",
    "spkts": 10, "dpkts": 8, "sbytes": 1500, "dbytes": 2000, ...
  }
}
"""
import sys, json, os, pickle
import numpy as np
import joblib

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
TEXT_MODEL  = os.path.join(SCRIPT_DIR, "model.pkl")
FLOW_MODEL  = os.path.join(SCRIPT_DIR, "flow_model.pkl")
ANOMALY_MODEL = os.path.join(SCRIPT_DIR, "anomaly_model.pkl")
ENCODERS    = os.path.join(SCRIPT_DIR, "label_encoders.pkl")

# Lazy-loaded singletons
_text_model   = None
_flow_data    = None
_anomaly      = None
_encoders     = None
_shap_explainer = None

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

# v3: log1p transforms applied during training — must apply at inference too
LOG_FEATURES_DEFAULT = [
    "sbytes","dbytes","sload","dload","rate","spkts","dpkts",
    "smean","dmean","response_body_len","sjit","djit",
]
ENGINEERED_FEATURES = ["bytes_ratio", "pkts_ratio", "byte_per_pkt", "conn_density"]

FEATURE_DESCRIPTIONS = {
    "smean":           "mean source packet size",
    "sbytes":          "total source bytes",
    "sttl":            "source TTL value",
    "service":         "network service",
    "proto":           "transport protocol",
    "ct_dst_src_ltm":  "conn count same dst+src (recent)",
    "ct_src_dport_ltm":"conn count same src+dport (recent)",
    "ct_srv_dst":      "conn count same service+dst (recent)",
    "ct_srv_src":      "conn count same service+src (recent)",
    "ct_dst_sport_ltm":"conn count same dst+sport (recent)",
    "dmean":           "mean destination packet size",
    "dload":           "destination bits per second",
    "synack":          "SYN→ACK round-trip time",
    "ct_src_ltm":      "conn count same source (recent)",
    "dbytes":          "total destination bytes",
    "rate":            "packets per second",
    "dur":             "connection duration (s)",
    "tcprtt":          "TCP round-trip time",
    "sload":           "source bits per second",
    "djit":            "destination jitter",
    "sjit":            "source jitter",
    # v3 engineered features
    "bytes_ratio":     "log(src bytes) / log(dst bytes) ratio",
    "pkts_ratio":      "log(src packets) / log(dst packets) ratio",
    "byte_per_pkt":    "log(src bytes) per log(src packet)",
    "conn_density":    "connection density (dst×src × service×src)",
}


def load_text_model():
    global _text_model
    if _text_model is None and os.path.exists(TEXT_MODEL):
        with open(TEXT_MODEL, "rb") as f:
            _text_model = pickle.load(f)
    return _text_model


def load_flow_data():
    global _flow_data, _shap_explainer, _encoders
    if _flow_data is None and os.path.exists(FLOW_MODEL):
        try:
            _flow_data = joblib.load(FLOW_MODEL)
            if _encoders is None and os.path.exists(ENCODERS):
                _encoders = joblib.load(ENCODERS)
            try:
                import shap
                # Prefer LightGBM for SHAP (faster TreeExplainer, better multiclass)
                shap_model = _flow_data.get("lgb") or _flow_data.get("xgb")
                _shap_explainer = shap.TreeExplainer(shap_model)
            except Exception as e:
                sys.stderr.write(f"[SHAP init] {e}\n")
                _shap_explainer = None
        except Exception as e:
            sys.stderr.write(f"[Flow model load error] {e}\n")
            _flow_data = None
    elif not os.path.exists(FLOW_MODEL):
        sys.stderr.write(f"[Flow model] not found at {FLOW_MODEL}\n")
    return _flow_data


def load_anomaly():
    global _anomaly
    if _anomaly is None and os.path.exists(ANOMALY_MODEL):
        _anomaly = joblib.load(ANOMALY_MODEL)
    return _anomaly


def encode_flow_features(features: dict) -> np.ndarray:
    """Convert raw feature dict to model input vector (v3: log1p + engineered features)."""
    fd = load_flow_data()
    enc = _encoders or {}

    # Determine what transforms to apply from model metadata (v3 stores these)
    log_feats = set(fd.get("log_features", LOG_FEATURES_DEFAULT) if fd else LOG_FEATURES_DEFAULT)
    has_engineered = fd is not None and "engineered_features" in fd

    # Build a dict of numeric values first (needed for engineered features)
    num_vals: dict[str, float] = {}
    for col in NUMERICAL_FEATURES:
        try:
            num_vals[col] = float(features.get(col, 0) or 0)
        except (TypeError, ValueError):
            num_vals[col] = 0.0

    row = []
    for col in ALL_FEATURES:
        if col in CATEGORICAL_FEATURES:
            le = enc.get(col)
            val_str = str(features.get(col, ""))
            if le is not None:
                known = list(le.classes_)
                val = float(known.index(val_str) if val_str in known else len(known))
            else:
                val = 0.0
        else:
            val = num_vals[col]
            if col in log_feats:
                val = float(np.log1p(max(0.0, val)))
        row.append(val)

    # Engineered features (computed after log1p, same as training)
    if has_engineered:
        sb = float(np.log1p(max(0.0, num_vals.get("sbytes", 0)))) if "sbytes" in log_feats else num_vals.get("sbytes", 0.0)
        db = float(np.log1p(max(0.0, num_vals.get("dbytes", 0)))) if "dbytes" in log_feats else num_vals.get("dbytes", 0.0)
        sp = float(np.log1p(max(0.0, num_vals.get("spkts", 0))))  if "spkts" in log_feats  else num_vals.get("spkts", 0.0)
        dp = float(np.log1p(max(0.0, num_vals.get("dpkts", 0))))  if "dpkts" in log_feats  else num_vals.get("dpkts", 0.0)
        ct_dst_src = num_vals.get("ct_dst_src_ltm", 0.0)
        ct_srv_src = num_vals.get("ct_srv_src", 0.0)
        row.append(sb / (db + 1e-6))                        # bytes_ratio
        row.append(sp / (dp + 1))                           # pkts_ratio
        row.append(sb / (sp + 1))                           # byte_per_pkt
        row.append((ct_dst_src + 1) * (ct_srv_src + 1))    # conn_density

    return np.array(row, dtype=np.float32).reshape(1, -1)


def predict_flow(features: dict) -> dict:
    """Predict from network flow features with SHAP explanation."""
    fd = load_flow_data()
    if fd is None:
        return None

    X = encode_flow_features(features)
    ensemble = fd["ensemble"]
    classes  = fd["classes"]

    proba    = ensemble.predict_proba(X)[0]
    top_idx  = int(np.argmax(proba))
    pred_cls = str(classes[top_idx])
    confidence = float(proba[top_idx])

    alternatives = [
        {"type": str(classes[i]), "confidence": round(float(proba[i]), 4)}
        for i in np.argsort(proba)[::-1]
        if str(classes[i]) != pred_cls
    ][:3]

    # Full feature names (including engineered) for SHAP index mapping
    feat_names = fd.get("feature_names", ALL_FEATURES)

    # SHAP explanation
    explanation = []
    if _shap_explainer is not None:
        try:
            shap_vals = np.array(_shap_explainer.shap_values(X))
            # shape: (1, features, classes) for LGB multiclass or (1, features)
            if shap_vals.ndim == 3:
                sv = shap_vals[0, :, top_idx]
            else:
                sv = shap_vals[0]
            top_shap = np.argsort(np.abs(sv))[::-1][:5]
            for fi in top_shap:
                fname = feat_names[fi] if fi < len(feat_names) else f"feature_{fi}"
                fval  = X[0, fi]
                explanation.append({
                    "feature":     fname,
                    "value":       round(float(fval), 4),
                    "impact":      round(float(sv[fi]), 4),
                    "description": FEATURE_DESCRIPTIONS.get(fname, fname),
                })
        except Exception as e:
            sys.stderr.write(f"[SHAP] {e}\n")

    # Anomaly score
    anomaly_score = None
    anomaly_flag  = False
    anomaly_model = load_anomaly()
    if anomaly_model is not None:
        try:
            score = float(anomaly_model.decision_function(X)[0])
            # Convert: -ve = anomaly. Normalize to 0-1 (higher = more anomalous)
            anomaly_score = round(max(0.0, min(1.0, (-score + 0.3) / 0.6)), 3)
            anomaly_flag  = bool(anomaly_model.predict(X)[0] == -1)
        except Exception as e:
            sys.stderr.write(f"[Anomaly] {e}\n")

    return {
        "type":         pred_cls,
        "confidence":   round(confidence, 4),
        "alternatives": alternatives,
        "explanation":  explanation,
        "anomalyScore": anomaly_score,
        "isAnomaly":    anomaly_flag,
        "mode":         "flow",
    }


def predict_text(text: str) -> dict:
    """Predict from raw log text using TF-IDF model."""
    model = load_text_model()
    if model is None:
        return _regex_fallback(text)

    classes = model.classes_
    proba   = model.predict_proba([text])[0]
    top_idx = int(np.argmax(proba))
    pred_cls = str(classes[top_idx])
    confidence = float(proba[top_idx])

    alternatives = [
        {"type": str(classes[i]), "confidence": round(float(proba[i]), 4)}
        for i in np.argsort(proba)[::-1]
        if str(classes[i]) != pred_cls
    ][:3]

    return {
        "type":         pred_cls,
        "confidence":   round(confidence, 4),
        "alternatives": alternatives,
        "explanation":  [],
        "anomalyScore": None,
        "isAnomaly":    False,
        "mode":         "text",
    }


REGEX_FALLBACK = [
    (r"brute.?force|password.?attempt|failed.?login|auth.?fail", "brute-force"),
    (r"sql.?inject|union.?select|1=1|drop.?table|xp_cmd",        "sql-injection"),
    (r"phish|spear|credential.?harvest|fake.?login",             "phishing"),
    (r"malware|trojan|ransomware|backdoor|c2.?connect",          "malware"),
    (r"ddos|flood|syn.?flood|amplif|botnet",                     "ddos"),
    (r"exfil|data.?leak|loot|exporting.?data",                   "data-exfiltration"),
    (r"priv.?esc|sudo.?exploit|privilege|escalat",               "privilege-escalation"),
    (r"unauthorized|invalid.?cred|access.?denied.+attempt",      "unauthorized-access"),
    (r"port.?scan|nmap|masscan|service.?discovery",              "port-scanning"),
    (r"cve-|exploit|vuln|remote.?code.?exec|rce",                "vulnerability-exploit"),
]

def _regex_fallback(text: str) -> dict:
    import re
    for pattern, attack_type in REGEX_FALLBACK:
        if re.search(pattern, text, re.IGNORECASE):
            return {"type": attack_type, "confidence": 0.65, "alternatives": [],
                    "explanation": [], "anomalyScore": None, "isAnomaly": False, "mode": "regex"}
    return {"type": "unauthorized-access", "confidence": 0.5, "alternatives": [],
            "explanation": [], "anomalyScore": None, "isAnomaly": False, "mode": "regex"}


def predict_hybrid(text: str, features: dict) -> dict:
    """Combine text + flow predictions with confidence weighting."""
    text_result = predict_text(text)
    flow_result = predict_flow(features) if features else None

    if flow_result is None:
        return text_result

    # Weighted combination: flow model (trained on real data) gets higher weight
    flow_w = 0.7
    text_w = 0.3

    # Gather all classes
    all_classes = set()
    all_classes.add(text_result["type"])
    all_classes.add(flow_result["type"])
    for a in text_result["alternatives"]:
        all_classes.add(a["type"])
    for a in flow_result["alternatives"]:
        all_classes.add(a["type"])

    # Build score maps
    text_scores = {text_result["type"]: text_result["confidence"]}
    for a in text_result["alternatives"]:
        text_scores[a["type"]] = a["confidence"]
    flow_scores = {flow_result["type"]: flow_result["confidence"]}
    for a in flow_result["alternatives"]:
        flow_scores[a["type"]] = a["confidence"]

    combined = {}
    for cls in all_classes:
        combined[cls] = flow_w * flow_scores.get(cls, 0.0) + text_w * text_scores.get(cls, 0.0)

    best = max(combined, key=combined.get)
    alts = sorted(
        [{"type": c, "confidence": round(v, 4)} for c, v in combined.items() if c != best],
        key=lambda x: -x["confidence"]
    )[:3]

    return {
        "type":         best,
        "confidence":   round(combined[best], 4),
        "alternatives": alts,
        "explanation":  flow_result.get("explanation", []),
        "anomalyScore": flow_result.get("anomalyScore"),
        "isAnomaly":    flow_result.get("isAnomaly", False),
        "mode":         "hybrid",
        "textType":     text_result["type"],
        "textConf":     text_result["confidence"],
        "flowType":     flow_result["type"],
        "flowConf":     flow_result["confidence"],
    }


def main():
    raw = sys.stdin.buffer.read().decode("utf-8-sig").strip()  # utf-8-sig handles BOM from PowerShell
    if not raw:
        print(json.dumps({"type": "unauthorized-access", "confidence": 0.5,
                          "alternatives": [], "explanation": [], "mode": "fallback"}))
        return

    # Try to parse as JSON (FLOW or HYBRID mode)
    features = None
    text = raw
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            features = parsed.get("features")
            text = parsed.get("text", raw)
    except (json.JSONDecodeError, ValueError):
        pass

    try:
        if features and text:
            result = predict_hybrid(text, features)
        elif features:
            result = predict_flow(features) or _regex_fallback("")
        else:
            # Try flow model if text-only, else text model
            result = predict_text(text)
        print(json.dumps(result))
    except Exception as e:
        sys.stderr.write(f"Prediction error: {e}\n")
        print(json.dumps(_regex_fallback(text)))


if __name__ == "__main__":
    main()
