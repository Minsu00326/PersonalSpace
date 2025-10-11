# handler.py — use only artifacts/pipeline.pkl (preprocessor + model)

import json, hashlib
from pathlib import Path
import joblib
from extract_features import extract_features_from_path  # your feature extractor

# === paths ===
BASE_DIR      = Path(__file__).resolve().parent.parent
PIPELINE_PATH = BASE_DIR / "artifacts" / "pipeline.pkl"
YARA_PATH     = BASE_DIR / "rules" / "packer.yar"

# optional default file for local test
PE_PATH       = Path("/home/alstn/SerialNumberDetectionTool.exe")

# --- file hashes ---
def file_hashes(p: Path):
    h1, h2 = hashlib.md5(), hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h1.update(chunk); h2.update(chunk)
    return h1.hexdigest(), h2.hexdigest()

# --- lazy load pipeline ---
_PIPE = None
def get_pipeline():
    global _PIPE
    if _PIPE is None:
        if not PIPELINE_PATH.exists():
            raise FileNotFoundError(f"pipeline.pkl not found: {PIPELINE_PATH}")
        _PIPE = joblib.load(PIPELINE_PATH)  # contains preprocessor + model
    return _PIPE

# --- local run ---
if __name__ == "__main__":
    pipe = get_pipeline()
    X = extract_features_from_path(str(PE_PATH), yara_rules_path=str(YARA_PATH))
    prob = float(pipe.predict_proba(X)[0, 1]); label = int(prob >= 0.5)
    md5, sha256 = file_hashes(PE_PATH)
    X_proc = pipe.named_steps["preprocessor"].transform(X)

    out = {
        "file": str(PE_PATH),
        "hashes": {"md5": md5, "sha256": sha256},
        "prediction": {"label": label, "prob": prob, "prob_percent": f"{prob*100:.2f}%"},
        "features_original": X.to_dict(orient="records")[0],
        "features_processed": X_proc.to_dict(orient="records")[0],
    }
    print(json.dumps(out, indent=2, ensure_ascii=False))

# --- AWS Lambda handler ---
def lambda_handler(event, context):
    pipe = get_pipeline()
    file_path = Path(event.get("file_path", str(PE_PATH)))
    X = extract_features_from_path(str(file_path), yara_rules_path=str(YARA_PATH))
    prob = float(pipe.predict_proba(X)[0, 1]); label = int(prob >= 0.5)
    md5, sha256 = file_hashes(file_path)

    out = {
        "file": str(file_path),
        "hashes": {"md5": md5, "sha256": sha256},
        "prediction": {"label": label, "prob": prob, "prob_percent": f"{prob*100:.2f}%"},
        "features_original": X.to_dict(orient="records")[0],
    }
    return {"statusCode": 200, "body": json.dumps(out, ensure_ascii=False)}
