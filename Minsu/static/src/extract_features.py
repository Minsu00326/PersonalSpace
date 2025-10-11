# extract_features.py — pefile ONLY + REQUIRED YARA
# - 헤더/임포트: pefile 풀 파싱(fast_load=False) + 임포트 디렉터리 명시 파싱
# - YARA: 반드시 규칙 파일을 로드해 스캔(경로 못 찾으면 예외)
# - 스키마 고정: artifacts/feature_list.txt (또는 인자로 지정)

from __future__ import annotations
from typing import Dict, Optional, Iterable
from pathlib import Path
import os, re, math
import pandas as pd

# ====== 경로/스키마 유틸 ======
def _first_exist(paths: Iterable[Path]) -> Optional[Path]:
    for p in paths:
        if p and p.exists():
            return p
    return None

def _resolve_feature_list_path(user_path: Optional[str|Path]=None) -> Path:
    if user_path:
        p = Path(user_path)
        if p.exists(): return p
    env = os.getenv("FEATURE_LIST_PATH")
    if env and Path(env).exists(): return Path(env)
    cwd = Path.cwd()
    cands = [
        cwd / "artifacts" / "feature_list.txt",
        cwd.parent / "artifacts" / "feature_list.txt",
        cwd.parent.parent / "artifacts" / "feature_list.txt",
    ]
    p = _first_exist(cands)
    if not p:
        raise FileNotFoundError("feature_list.txt을 찾지 못했습니다. FEATURE_LIST_PATH 환경변수나 인자로 경로를 지정하세요.")
    return p

_FEATURE_COLUMNS: Optional[list[str]] = None
def _load_feature_columns(feature_list_path: Optional[str|Path]=None) -> list[str]:
    global _FEATURE_COLUMNS
    if _FEATURE_COLUMNS is not None:
        return _FEATURE_COLUMNS
    path = _resolve_feature_list_path(feature_list_path)
    cols = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if not cols:
        raise ValueError("feature_list.txt is empty")
    _FEATURE_COLUMNS = cols
    return _FEATURE_COLUMNS

def _ensure_schema(row: Dict[str, float], feature_list_path: Optional[str|Path]=None) -> pd.DataFrame:
    cols = _load_feature_columns(feature_list_path)
    cleaned = {k: row.get(k, 0.0) for k in cols}
    df = pd.DataFrame([cleaned], columns=cols)
    for c in df.columns:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    return df.fillna(0.0)

# ====== 수치 유틸 ======
def _entropy(data: bytes | str) -> float:
    if data is None: return 0.0
    if isinstance(data, str):
        data = data.encode("utf-8", "ignore")
    n = len(data)
    if n == 0: return 0.0
    from collections import Counter
    ent = 0.0
    inv_log2 = 1.0 / math.log(2.0)
    for v in Counter(data).values():
        p = v / n
        ent -= p * (math.log(p) * inv_log2)
    return float(ent)

# ====== 필수 의존성: pefile / yara ======
try:
    import pefile
except Exception as e:
    raise ImportError("pefile가 필요합니다. pip install pefile") from e

try:
    import yara
except Exception as e:
    raise ImportError("yara-python이 필요합니다. pip install yara-python") from e

# ====== YARA ======
_YARA_RULES = None

def _resolve_yara_rules_path(yara_rules_path: Optional[str|Path]) -> Path:
    # 반드시 규칙 파일이 있어야 한다(없으면 예외)
    cands = []
    if yara_rules_path: cands.append(Path(yara_rules_path))
    env = os.getenv("YARA_RULES_PATH")
    if env: cands.append(Path(env))
    cwd = Path.cwd()
    cands += [
        cwd / "rules" / "packer.yar",
        cwd.parent / "rules" / "packer.yar",
        cwd.parent.parent / "rules" / "packer.yar",
    ]
    p = _first_exist(cands)
    if not p:
        raise FileNotFoundError("YARA 규칙 파일을 찾지 못했습니다. YARA_RULES_PATH 환경변수 또는 인자로 정확한 경로를 지정하세요.")
    return p

def _get_yara_rules(yara_rules_path: Optional[str|Path]) -> "yara.Rules":
    global _YARA_RULES
    if _YARA_RULES is None:
        p = _resolve_yara_rules_path(yara_rules_path)
        _YARA_RULES = yara.compile(filepaths={"ns0": str(p.resolve())})
    return _YARA_RULES

def _scan_packer_yara(raw: bytes, rules: "yara.Rules") -> Dict[str, int]:
    out = {
        "yara_has_packer_generic": 0,
        "yara_count_packer": 0,
        "yara_has_upx_like": 0,
        "yara_has_mpress_like": 0,
        "yara_has_aspack_like": 0,
    }
    try:
        matches = rules.match(data=raw, timeout=10)
        if not matches:
            return out
        uniq = {(m.namespace, m.rule) for m in matches}
        out["yara_count_packer"] = len(uniq)
        if out["yara_count_packer"] > 0:
            out["yara_has_packer_generic"] = 1
        tokens, names = [], []
        for m in matches:
            names.append(m.rule)
            tokens.append(m.rule.lower())
            tokens.extend([t.lower() for t in m.tags])
        s = " ".join(tokens)
        out["yara_has_upx_like"]    = 1 if "upx" in s else 0
        out["yara_has_aspack_like"] = 1 if "aspack" in s else 0
        mpress_re = re.compile(r'(?<![A-Za-z0-9])mpress(?![A-Za-z0-9])', re.I)
        out["yara_has_mpress_like"] = 1 if ("mpress" in s) or any(mpress_re.search(n) for n in names) else 0
    except Exception:
        # YARA 실패 시 예외 전파 대신 0으로
        pass
    return out

# ====== 헤더/임포트/문자열 ======
_HEADER_KEYS = [
    "DllCharacteristics","MajorImageVersion","MajorOperatingSystemVersion",
    "SizeOfStackReserve","AddressOfEntryPoint","Characteristics",
    "SizeOfHeaders","SizeOfInitializedData","SizeOfUninitializedData",
    "MinorSubsystemVersion","ImageBase","MajorLinkerVersion",
    "NumberOfSections","MinorImageVersion","SizeOfStackCommit",
    "e_lfanew","e_minalloc","e_ovno","Machine","PointerToSymbolTable","NumberOfSymbols",
    "SizeOfCode","BaseOfCode","SectionAlignment","FileAlignment",
]

def _extract_headers_pefile(file_bytes: bytes) -> Dict[str, float]:
    feats: Dict[str, float] = {}
    pe = None
    try:
        # 풀 파싱 고정
        pe = pefile.PE(data=file_bytes, fast_load=False)
        DOS  = getattr(pe, "DOS_HEADER", None)
        FILE = getattr(pe, "FILE_HEADER", None)
        OPT  = getattr(pe, "OPTIONAL_HEADER", None)
        g = lambda obj, attr, d=-1: getattr(obj, attr, d) if obj else d
        feats.update({
            "DllCharacteristics": g(OPT,"DllCharacteristics"),
            "MajorImageVersion": g(OPT,"MajorImageVersion"),
            "MajorOperatingSystemVersion": g(OPT,"MajorOperatingSystemVersion"),
            "SizeOfStackReserve": g(OPT,"SizeOfStackReserve"),
            "AddressOfEntryPoint": g(OPT,"AddressOfEntryPoint"),
            "Characteristics": g(FILE,"Characteristics"),
            "SizeOfHeaders": g(OPT,"SizeOfHeaders"),
            "SizeOfInitializedData": g(OPT,"SizeOfInitializedData"),
            "SizeOfUninitializedData": g(OPT,"SizeOfUninitializedData"),
            "MinorSubsystemVersion": g(OPT,"MinorSubsystemVersion"),
            "ImageBase": g(OPT,"ImageBase"),
            "MajorLinkerVersion": g(OPT,"MajorLinkerVersion"),
            "NumberOfSections": g(FILE,"NumberOfSections"),
            "MinorImageVersion": g(OPT,"MinorImageVersion"),
            "SizeOfStackCommit": g(OPT,"SizeOfStackCommit"),
            "e_lfanew": g(DOS,"e_lfanew"),
            "e_minalloc": g(DOS,"e_minalloc"),
            "e_ovno": g(DOS,"e_ovno"),
            "Machine": g(FILE,"Machine"),
            "PointerToSymbolTable": g(FILE,"PointerToSymbolTable"),
            "NumberOfSymbols": g(FILE,"NumberOfSymbols"),
            "SizeOfCode": g(OPT,"SizeOfCode"),
            "BaseOfCode": g(OPT,"BaseOfCode"),
            "SectionAlignment": g(OPT,"SectionAlignment"),
            "FileAlignment": g(OPT,"FileAlignment"),
        })
    except Exception:
        for k in _HEADER_KEYS: feats[k] = -1
    finally:
        if pe:
            try: pe.close()
            except Exception: pass
    return feats

def _extract_imports_pefile(file_bytes: bytes) -> Dict[str, float]:
    all_imports, dlls, imports_per_dll = [], set(), []
    try:
        pe2 = pefile.PE(data=file_bytes, fast_load=True)
        # 임포트 디렉터리 명시 파싱(환경/버전 차이 방지)
        try:
            pe2.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
            ])
        except Exception:
            pass
        if hasattr(pe2, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe2.DIRECTORY_ENTRY_IMPORT:
                name = (entry.dll or b"").decode("utf-8","ignore").lower()
                if name: dlls.add(name)
                cnt = 0
                for imp in entry.imports:
                    if imp.name:
                        all_imports.append(imp.name.decode("utf-8","ignore")); cnt += 1
                if cnt > 0: imports_per_dll.append(cnt)
        try: pe2.close()
        except Exception: pass
    except Exception:
        pass

    return {
        "imports_total": len(all_imports),
        "imports_unique": len(set(all_imports)),
        "import_dlls_unique": len(dlls),
        "imports_max_per_dll": max(imports_per_dll) if imports_per_dll else 0,
        "imports_entropy": _entropy(''.join(all_imports)) if all_imports else 0.0,
    }

def _extract_strings(file_bytes: bytes) -> Dict[str, float]:
    strings = re.findall(rb"[\x20-\x7e]{4,}", file_bytes)
    if strings:
        printable_len = sum(len(s) for s in strings)
        return {
            "strings_entropy": _entropy(b"".join(strings)),
            "strings_printable_ratio": (printable_len / len(file_bytes)) if file_bytes else 0.0,
            "strings_avg_len": (printable_len / len(strings)) if strings else 0.0,
            "strings_base64_blob_count": len(re.findall(rb'[A-Za-z0-9+/=]{20,}', file_bytes)),
        }
    else:
        return {
            "strings_entropy": 0.0,
            "strings_printable_ratio": 0.0,
            "strings_avg_len": 0.0,
            "strings_base64_blob_count": 0,
        }

# ====== 공개 API ======
def extract_features_from_bytes(
    file_bytes: bytes,
    yara_rules_path: Optional[str|Path]=None,
    feature_list_path: Optional[str|Path]=None,
) -> pd.DataFrame:
    feats: Dict[str, float] = {}
    feats.update(_extract_headers_pefile(file_bytes))
    feats.update(_extract_imports_pefile(file_bytes))
    feats.update(_extract_strings(file_bytes))
    # YARA: 반드시 규칙 로드해 스캔
    rules = _get_yara_rules(yara_rules_path)
    feats.update(_scan_packer_yara(file_bytes, rules))
    return _ensure_schema(feats, feature_list_path)

def extract_features_from_path(
    file_path: str|Path,
    yara_rules_path: Optional[str|Path]=None,
    feature_list_path: Optional[str|Path]=None,
) -> pd.DataFrame:
    p = Path(file_path)
    if ":" in p.name:
        raise ValueError(f"Unsupported filename with colon (ADS?): {p}")
    with open(p, "rb") as f:
        data = f.read()
    return extract_features_from_bytes(data, yara_rules_path, feature_list_path)

def df_to_dict(df: pd.DataFrame) -> Dict[str, float]:
    cols = _load_feature_columns()
    assert df.shape[0] == 1, "df must be a single-row DataFrame"
    out = {}
    for c in cols:
        out[c] = float(pd.to_numeric(df.iloc[0][c], errors="coerce")) if c in df.columns else 0.0
    return out
