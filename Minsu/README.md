# Malware Detection - Static Analysis

```text
- PE 파일 정적 분석 기반 악성코드 탐지를 위한 파이프라인입니다.
- PE 헤더, Import API, 문자열 통계, YARA 패커 탐지 피처를 추출하여 최종적으로 학습된 XGBoost 모델을 사용해 악성/정상을 분류합니다.
```

## 디렉토리 구조
```text
static/
├─ artifacts/                # 모델 및 피처 관련 산출물
│  ├─ pipeline.pkl           # 전처리 및 학습된 XGBoost 모델 파이프라인 
│  └─ feature_list.txt       # 최종 피처 목록 (순서 고정)
│
├─ src/
│  ├─ extract_features.py    # PE 피처 추출 코드
│  └─ handler.py             # 실행 및 AWS Lambda 핸들러
│
└─ rules/
   └─ packer.yar             # 패커 탐지용 YARA 룰
```

## 실행 환경 준비
```bash
# 가상환경 생성 및 활성화
python3 -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate

# 필요 라이브러리 설치
pip install -r requirements.txt
```

## 실행 방법
```bash
# handler.py 속 PE_PATH를 수정해 사용 
python src/handler.py
```

## 예측 결과 예시
```json
{
  "file": "/home/alstn/SerialNumberDetectionTool.exe",
  "hashes": {
    "md5": "72a03d0cd0bb0745704bbb02bb161187",
    "sha256": "e272684dbbd922d828968bbc7db79fe495fbc5cdad25f91bddb6a603558278fd"
  },
  "prediction": {
    "label": 1,
    "prob": 0.9463813900947571,
    "prob_percent": "94.64%"
  },
  "features_original": {
    "DllCharacteristics": 34112,
    "SizeOfStackReserve": 1048576,
    "AddressOfEntryPoint": 94062,
    "Characteristics": 258,
    "SizeOfHeaders": 512,
    "SizeOfInitializedData": 2048,
    "SizeOfUninitializedData": 0,
    "SizeOfStackCommit": 4096,
    "SizeOfCode": 86016,
    "BaseOfCode": 8192,
    "SectionAlignment": 8192,
    "FileAlignment": 512,
    "ImageBase": 4194304,
    "PointerToSymbolTable": 0,
    "NumberOfSymbols": 0,
    "imports_total": 1,
    "imports_unique": 1,
    "import_dlls_unique": 1,
    "imports_max_per_dll": 1,
    "strings_avg_len": 34.50093574547723,
    "strings_base64_blob_count": 483,
    "e_minalloc": 0,
    "e_ovno": 0,
    "MinorImageVersion": 0,
    "MajorImageVersion": 0,
    "MajorOperatingSystemVersion": 4,
    "MinorSubsystemVersion": 0,
    "MajorLinkerVersion": 11,
    "NumberOfSections": 3,
    "Machine": 332,
    "imports_entropy": 3.459431618637298,
    "strings_entropy": 5.694874297603873,
    "strings_printable_ratio": 0.5755182317682318,
    "yara_has_packer_generic": 1,
    "yara_count_packer": 1,
    "yara_has_upx_like": 0,
    "yara_has_mpress_like": 0,
    "yara_has_aspack_like": 0,
    "e_lfanew": 128
  }
```