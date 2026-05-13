import json, os
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(SCRIPT_DIR, "flow_model_metadata.json")) as f:
    meta = json.load(f)
print("Current accuracy:", meta["accuracy"])
print("F1 weighted:     ", meta["f1Weighted"])
print("F1 macro:        ", meta["f1Macro"])
print()
print("Per-class metrics (sorted by F1):")
for cls, m in sorted(meta.get("perClassMetrics", {}).items(), key=lambda x: x[1]["f1"]):
    bar = "#" * int(m["f1"] * 20)
    print(f"  {cls:<28} P={m['precision']:.2f}  R={m['recall']:.2f}  F1={m['f1']:.2f}  n={m['support']:<6}  {bar}")
