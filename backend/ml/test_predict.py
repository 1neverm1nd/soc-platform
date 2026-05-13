"""Quick test of all prediction modes."""
import json, subprocess, sys

def run(inp):
    r = subprocess.run([sys.executable, "predict.py"], input=inp, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        print("STDERR:", r.stderr[:300])
    return json.loads(r.stdout) if r.stdout.strip() else {}

print("=== TEXT mode: brute force ===")
r = run("brute force attack: 50 failed login attempts from 10.0.1.5")
print(f"  type={r['type']} conf={r['confidence']:.3f} mode={r['mode']}")

print("\n=== TEXT mode: SQL injection ===")
r = run("SELECT * FROM users WHERE id=1 UNION SELECT username,password FROM admin--")
print(f"  type={r['type']} conf={r['confidence']:.3f} mode={r['mode']}")

print("\n=== FLOW mode: DoS/DDoS features ===")
flow_inp = json.dumps({
    "features": {
        "proto": "udp", "service": "-", "state": "INT",
        "dur": 0.001, "spkts": 5000, "dpkts": 0,
        "sbytes": 250000, "dbytes": 0, "rate": 5000000,
        "sttl": 64, "dttl": 0, "smean": 50, "dmean": 0,
        "sload": 1000000000.0, "dload": 0,
        "ct_srv_src": 50, "ct_dst_src_ltm": 100, "ct_dst_sport_ltm": 100,
    }
})
r = run(flow_inp)
print(f"  type={r['type']} conf={r['confidence']:.3f} mode={r['mode']}")
print(f"  anomaly_score={r.get('anomalyScore')} is_anomaly={r.get('isAnomaly')}")
if r.get("explanation"):
    print("  Top SHAP features:")
    for ex in r["explanation"][:3]:
        print(f"    {ex['feature']}: {ex['value']} (impact={ex['impact']:.3f})")

print("\n=== HYBRID mode: text + flow ===")
hybrid_inp = json.dumps({
    "text": "malware C2 callback detected",
    "features": {
        "proto": "tcp", "service": "-", "state": "CON",
        "dur": 120, "spkts": 20, "dpkts": 20,
        "sbytes": 5000, "dbytes": 5000, "rate": 0.5,
        "sttl": 64, "dttl": 252, "smean": 250, "dmean": 250,
        "ct_srv_src": 1, "ct_dst_src_ltm": 1,
    }
})
r = run(hybrid_inp)
print(f"  type={r['type']} conf={r['confidence']:.3f} mode={r['mode']}")
print(f"  text={r.get('textType')}({r.get('textConf'):.2f}) flow={r.get('flowType')}({r.get('flowConf'):.2f})")

print("\nAll tests passed!")
