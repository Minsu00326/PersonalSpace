import os, json, hashlib
import joblib
import boto3
from pathlib import Path
from src.extract_features import extract_features_from_path
from src.transformers import log_transform, remove_feature_prefixes
import pandas as pd
import numpy as np 



# === 경로 설정 ===
BASE_DIR      = Path(__file__).resolve().parent.parent
PIPELINE_PATH = BASE_DIR / "artifacts" / "pipeline.pkl" 
YARA_PATH     = BASE_DIR / "rules" / "packer.yar"

# --- 해시 함수 ---
def file_hashes(file_path: Path):
    file_path = Path(file_path)
    h_md5 = hashlib.md5()
    h_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            h_md5.update(chunk)
            h_sha256.update(chunk)
    return h_md5.hexdigest(), h_sha256.hexdigest()


# === AWS Lambda 핸들러 ===
def lambda_handler(event, context):
    try:
        s3 = boto3.client("s3")

        # 1. 모델 로드
        pipeline = joblib.load(PIPELINE_PATH)

        # 2. S3 이벤트에서 bucket, key 추출
        record = event["Records"][0]
        bucket = record["s3"]["bucket"]["name"]
        key    = record["s3"]["object"]["key"]

        # 3. 로컬 임시 경로에 파일 저장
        local_path = f"/tmp/{os.path.basename(key)}"
        s3.download_file(bucket, key, local_path)

        # 4. 피처 추출
        X_one = extract_features_from_path(local_path, yara_rules_path=str(YARA_PATH))

        # 5. 추론
        prob  = float(pipeline.predict_proba(X_one)[0, 1])
        label = int(prob >= 0.5)

        # 6. 해시 계산
        md5, sha256 = file_hashes(local_path)

        # 7. 결과 JSON 생성
        result = {
            "file": key,
            "hashes": {"md5": md5, "sha256": sha256},
            "prediction": {
                "label": "malicious" if label == 1 else "benign",
                "prob": prob,
                "prob_percent": f"{prob*100:.2f}%"
            },
            "features_original": X_one.to_dict(orient="records")[0]
        }

        # 8. 결과를 S3 업로드
        result_key = f"AI_Result/PE/{os.path.basename(key).replace('.exe', '_result.json')}"
        result_local = "/tmp/result.json"
        with open(result_local, "w") as f:
            json.dump(result, f, ensure_ascii=False)

        s3.upload_file(result_local, "fit-bool-p", result_key)

        return {"statusCode": 200, "body": json.dumps(result, ensure_ascii=False)}

    except Exception as e:
        print("❌ Error:", str(e))
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
