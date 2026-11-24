"""nuclei POC 模板库：用户导入的 YAML 落在 DATA_DIR/pocs，按分类目录归档。

布局：DATA_DIR/pocs/<分类>/<文件名>.yaml，分类最多三层；根目录下的文件算「未分类」。
nuclei 的 ``-t`` 指向库根目录，会递归加载所有分类，所以加分类不影响扫描。
文件名只挡 Windows 不允许的字符，中文、空格、括号、加号都保留。
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from pathlib import Path

import yaml

from ..config import DATA_DIR

POC_DIR = DATA_DIR / "pocs"

# 一条模板至少得有触发段，否则 nuclei 加载时直接报错
EXEC_KEYS = ("requests", "http", "network", "dns", "tcp", "file", "headless",
             "javascript", "code", "ssl", "websocket", "whois")

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]

MAX_CATEGORY_DEPTH = 3
MAX_SEGMENT = 40
MAX_STEM = 100
LIST_DESC_CHARS = 160
IMPORT_DETAIL = 200

_BAD_CHARS = set('<>:"/\\|?*') | {chr(i) for i in range(32)}
_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}

# list 时按 (mtime, size) 复用解析结果：几万条模板不必每次请求全量 YAML 解析
_CACHE: dict[str, tuple[float, int, dict]] = {}


def pocs_dir() -> Path:
    POC_DIR.mkdir(parents=True, exist_ok=True)
    return POC_DIR


def _clean_segment(seg: str) -> str:
    out = "".join("-" if c in _BAD_CHARS else c for c in str(seg or ""))
    return out.strip().strip(" .")


def safe_category(cat: str) -> str:
    """分类名：允许中文和常见符号，去掉 Windows 非法字符，最多三层。"""
    raw = str(cat or "").replace("\\", "/").strip().strip("/")
    if not raw:
        return ""
    parts: list[str] = []
    for seg in raw.split("/"):
        seg = _clean_segment(seg)
        if not seg or seg in {".", ".."}:
            continue
        if len(seg) > MAX_SEGMENT:
            seg = seg[:MAX_SEGMENT].rstrip(" .")
        parts.append(seg)
        if len(parts) >= MAX_CATEGORY_DEPTH:
            break
    return "/".join(parts)


def safe_filename(name: str) -> str:
    """文件名：只替换 Windows 非法字符，中文 / 空格 / 括号 / 加号都保留。"""
    base = str(name or "").replace("\\", "/").split("/")[-1].strip()
    if not base:
        raise ValueError("文件名不能为空")
    stem, ext = os.path.splitext(base)
    if ext.lower() not in (".yaml", ".yml"):
        stem = base
    stem = _clean_segment(stem)
    if not stem:
        raise ValueError("文件名不能为空")
    if stem.upper() in _RESERVED:
        stem = "_" + stem
    if len(stem) > MAX_STEM:
        # 截断后加原名摘要，避免两个长文件名截成同一个把前一份覆盖掉
        digest = hashlib.md5(stem.encode("utf-8")).hexdigest()[:8]
        stem = stem[: MAX_STEM - len(digest) - 1].rstrip(" .") + "-" + digest
    return stem + ".yaml"


def name_ok(name: str) -> bool:
    try:
        safe_filename(name)
        return True
    except ValueError:
        return False


def _split_target(target: str, category: str = "") -> tuple[str, str]:
    raw = str(target or "").replace("\\", "/").strip().strip("/")
    if "/" in raw:
        cat, name = raw.rsplit("/", 1)
        return safe_category(cat), safe_filename(name)
    return safe_category(category), safe_filename(raw)


def _rel(target: str, category: str = "") -> Path:
    cat, name = _split_target(target, category)
    return Path(cat, name) if cat else Path(name)


def _abs(rel: Path) -> Path:
    root = pocs_dir().resolve()
    p = (root / rel).resolve()
    if p != root and root not in p.parents:
        raise ValueError("模板路径不合法")
    return p


def _category_of(rel: str) -> str:
    parent = Path(rel).parent.as_posix()
    return "" if parent == "." else parent


def _meta(text: str) -> tuple[dict, str]:
    """解析模板头；返回 (元数据, 错误)。错误非空表示这条模板 nuclei 也加载不了。"""
    try:
        doc = yaml.safe_load(text)
    except Exception as e:
        return {}, f"YAML 解析失败：{e}"
    if not isinstance(doc, dict):
        return {}, "模板必须是一个 YAML 映射"
    tid = str(doc.get("id") or "").strip()
    info = doc.get("info")
    if not tid:
        return {}, "缺少 id 字段"
    if not isinstance(info, dict):
        return {}, "缺少 info 字段"
    if not any(k in doc for k in EXEC_KEYS):
        return {}, "缺少请求段（requests / http / network / dns 等）"
    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in re.split(r"[,，\s]+", tags) if t.strip()]
    return {
        "id": tid,
        "title": str(info.get("name") or tid),
        "severity": str(info.get("severity") or "unknown").lower(),
        "author": str(info.get("author") or ""),
        "description": str(info.get("description") or "").strip(),
        "tags": [str(t) for t in tags][:20],
        "reference": str(info.get("reference") or ""),
    }, ""


def _summary(text: str) -> tuple[dict, str]:
    meta, err = _meta(text)
    if meta.get("severity") not in SEVERITY_ORDER:
        meta["severity"] = "unknown"
    return meta, err


def _row(p: Path) -> dict | None:
    rel = p.relative_to(pocs_dir()).as_posix()
    try:
        st = p.stat()
        hit = _CACHE.get(rel)
        if hit and hit[0] == st.st_mtime and hit[1] == st.st_size:
            return dict(hit[2])
        text = p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None
    meta, err = _summary(text)
    row = {
        "name": p.name,
        "path": rel,
        "category": _category_of(rel),
        "bytes": st.st_size,
        "mtime": int(st.st_mtime),
        "updated": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)),
        "ok": not err,
        "error": err,
        **meta,
    }
    row["description"] = row["description"][:LIST_DESC_CHARS]
    _CACHE[rel] = (st.st_mtime, st.st_size, dict(row))
    return row


def list_pocs() -> list[dict]:
    rows: list[dict] = []
    for p in sorted(pocs_dir().rglob("*.y*ml")):
        if not p.is_file():
            continue
        r = _row(p)
        if r:
            rows.append(r)
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    rows.sort(key=lambda r: (rank.get(r.get("severity") or "unknown", 99),
                             r.get("category") or "", r["name"].lower()))
    return rows


def read_poc(target: str, category: str = "") -> dict:
    rel = _rel(target, category)
    p = _abs(rel)
    if not p.is_file():
        raise FileNotFoundError(target)
    text = p.read_text(encoding="utf-8", errors="ignore")
    meta, err = _summary(text)
    return {"name": p.name, "path": rel.as_posix(), "category": _category_of(rel.as_posix()),
            "content": text, "ok": not err, "error": err, **meta}


def save_poc(name: str, content: str, category: str = "", old: str = "") -> dict:
    """保存到「分类/文件名」；old 是编辑前的相对路径，换了分类时把旧文件挪走。"""
    rel = _rel(name, category)
    p = _abs(rel)
    # Windows 记事本 / 部分仓库导出的 YAML 带 BOM，nuclei 和 PyYAML 都不认，直接吃掉
    text = (content or "").replace("\r\n", "\n").lstrip("\ufeff").strip() + "\n"
    meta, err = _meta(text)
    if err:
        raise ValueError(err)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8", newline="\n")
    rel_s = rel.as_posix()
    _CACHE.pop(rel_s, None)
    if old and str(old).replace("\\", "/").strip("/") != rel_s:
        try:
            old_p = _abs(_rel(str(old), category))
            if old_p.is_file():
                old_p.unlink()
                _CACHE.pop(str(old).replace("\\", "/").strip("/"), None)
        except (ValueError, FileNotFoundError):
            pass
    return {"name": p.name, "path": rel_s, "category": _category_of(rel_s),
            "bytes": p.stat().st_size, "ok": True, **meta}


def delete_poc(target: str, category: str = "") -> dict:
    rel = _rel(target, category)
    p = _abs(rel)
    if not p.is_file():
        raise FileNotFoundError(target)
    p.unlink()
    _CACHE.pop(rel.as_posix(), None)
    return {"name": p.name, "path": rel.as_posix(), "category": _category_of(rel.as_posix())}


def split_docs(text: str) -> list[str]:
    """多文档合并粘贴：按 ``---`` 分隔行拆成单条模板。"""
    chunks = re.split(r"(?m)^---[ \t]*$", (text or "").replace("\r\n", "\n"))
    return [c.strip().lstrip("\ufeff").strip() for c in chunks if c.strip()]


def import_many(text: str) -> dict:
    """批量导入：每条 doc 按自己的 id 命名，失败的单条记下来不打断其余。"""
    saved, failed = [], []
    for chunk in split_docs(text):
        meta, err = _meta(chunk)
        if err:
            failed.append({"error": err, "head": chunk.splitlines()[0][:80] if chunk else ""})
            continue
        name = re.sub(r"[^A-Za-z0-9_.\-]+", "-", meta["id"]).strip("-") or "poc"
        try:
            saved.append(save_poc(name + ".yaml", chunk))
        except ValueError as e:
            failed.append({"error": str(e), "head": meta.get("id", "")})
    return {"saved": saved, "failed": failed, "count": len(saved)}


MAX_FILE_BYTES = 1024 * 1024


def _file_basename(name: str) -> str:
    return (name or "").replace("\\", "/").split("/")[-1].strip()


def _save_doc(chunk: str, preferred: str, origin: str, category: str,
              saved: list, failed: list) -> None:
    """单条 doc 入库：优先用用户选的文件名，文件名不可用再退回模板 id。"""
    meta, err = _meta(chunk)
    if err:
        failed.append({"file": origin, "error": err,
                       "head": (chunk.splitlines() or [""])[0][:80]})
        return
    id_name = (re.sub(r"[^A-Za-z0-9_.\-]+", "-", meta["id"]).strip("-") or "poc") + ".yaml"
    names = []
    if preferred:
        try:
            names.append(safe_filename(preferred))
        except ValueError:
            pass
    try:
        id_name = safe_filename(id_name)
    except ValueError:
        pass
    if id_name not in names:
        names.append(id_name)
    last = ""
    for n in names:
        try:
            existed = _abs(_rel(n, category)).exists()
            saved.append({"file": origin, "overwritten": existed, **save_poc(n, chunk, category)})
            return
        except ValueError as e:
            last = str(e)
    failed.append({"file": origin, "error": last or "保存失败", "head": meta.get("id", "")})


def import_files(files: list[dict]) -> tuple[list, list]:
    """按文件导入：每个文件可能含多份模板；category 或 path 里的目录决定分类。"""
    saved: list = []
    failed: list = []
    for item in files or []:
        if not isinstance(item, dict):
            continue
        origin = _file_basename(str(item.get("name") or ""))
        # 界面会显式给 category（可能是空 = 未分类）；没这个键时按 path 里的目录兜底
        if "category" in item:
            cat_raw = str(item.get("category") or "")
        else:
            cat_raw = ""
            if item.get("path"):
                rel = str(item.get("path") or "").replace("\\", "/").strip("/")
                cat_raw = "/".join(rel.split("/")[:-1])
        category = safe_category(cat_raw)
        text = str(item.get("content") or "")
        if len(text.encode("utf-8", "ignore")) > MAX_FILE_BYTES:
            failed.append({"file": origin, "error": "文件超过 1 MB，跳过"})
            continue
        docs = split_docs(text)
        if not docs:
            failed.append({"file": origin, "error": "文件里没有模板内容"})
            continue
        preferred = origin if len(docs) == 1 else ""
        for chunk in docs:
            _save_doc(chunk, preferred, origin, category, saved, failed)
    return saved, failed


def import_batch(text: str, files: list[dict] | None = None) -> dict:
    """批量入口：文件在前、粘贴在后；回包只带前 200 条明细，避免几万条把响应撑爆。"""
    saved, failed = import_files(files or [])
    if (text or "").strip():
        out = import_many(text)
        for s in out["saved"]:
            saved.append({"file": "", "overwritten": False, **s})
        for f in out["failed"]:
            failed.append({"file": "粘贴内容", **f})
    return {"saved": saved[:IMPORT_DETAIL], "failed": failed,
            "count": len(saved), "truncated": max(0, len(saved) - IMPORT_DETAIL)}


def scan_dirs() -> list[str]:
    """nuclei 的 ``-t`` 目录：用户库在前（递归含分类子目录），本机默认模板目录有就一起叠加。"""
    out: list[str] = []
    d = pocs_dir()
    if any(d.rglob("*.y*ml")):
        out.append(str(d))
    cands = [os.environ.get("NUCLEI_TEMPLATES") or "", str(Path.home() / "nuclei-templates")]
    for c in cands:
        try:
            p = Path(c)
            if c and p.is_dir() and str(p.resolve()) not in {str(Path(x).resolve()) for x in out}:
                out.append(str(p))
        except Exception:
            continue
    return out
