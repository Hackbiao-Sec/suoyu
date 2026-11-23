"""nuclei POC 模板库：用户导入的 YAML 落在 DATA_DIR/pocs。

打包后 arlx 目录在 _MEIPASS 里、进程结束就没了，所以模板统一放数据目录；
nuclei 扫描时用 ``-t`` 直接指向这个目录，界面里保存的 POC 立刻生效。
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

import yaml

from ..config import DATA_DIR

POC_DIR = DATA_DIR / "pocs"

# 只允许一级 yaml 文件名，堵住 ../ 之类的路径穿越
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,119}\.(ya?ml)$")

# 一条模板至少得有触发段，否则 nuclei 加载时直接报错
EXEC_KEYS = ("requests", "http", "network", "dns", "tcp", "file", "headless",
             "javascript", "code", "ssl", "websocket", "whois")

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


def pocs_dir() -> Path:
    POC_DIR.mkdir(parents=True, exist_ok=True)
    return POC_DIR


def name_ok(name: str) -> bool:
    return bool(NAME_RE.match(name or ""))


def normalize_name(name: str) -> str:
    """补 .yaml、拒绝穿越；中文模板名转成 id 由调用方决定，这里只管文件安全。"""
    n = (name or "").strip().replace("\\", "/").split("/")[-1]
    if not n:
        raise ValueError("模板名不能为空")
    if not n.lower().endswith((".yaml", ".yml")):
        n += ".yaml"
    if not name_ok(n):
        raise ValueError("模板名只能用字母、数字、下划线、点和减号，且必须以字母或数字开头")
    return n


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


def list_pocs() -> list[dict]:
    rows: list[dict] = []
    for p in sorted(pocs_dir().glob("*.y*ml")):
        try:
            st = p.stat()
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        meta, err = _summary(text)
        rows.append({
            "name": p.name,
            "bytes": st.st_size,
            "mtime": int(st.st_mtime),
            "updated": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)),
            "ok": not err,
            "error": err,
            **meta,
        })
    sev = {s: 0 for s in SEVERITY_ORDER}
    for r in rows:
        sev[r.get("severity") or "unknown"] = sev.get(r.get("severity") or "unknown", 0) + 1
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    rows.sort(key=lambda r: (rank.get(r.get("severity") or "unknown", 99), r["name"].lower()))
    return rows


def read_poc(name: str) -> dict:
    if not name_ok(name):
        raise ValueError("模板名不合法")
    p = pocs_dir() / name
    if not p.exists():
        raise FileNotFoundError(name)
    text = p.read_text(encoding="utf-8", errors="ignore")
    meta, err = _summary(text)
    return {"name": p.name, "content": text, "ok": not err, "error": err, **meta}


def save_poc(name: str, content: str) -> dict:
    n = normalize_name(name)
    text = (content or "").replace("\r\n", "\n").strip() + "\n"
    meta, err = _meta(text)
    if err:
        raise ValueError(err)
    p = pocs_dir() / n
    p.write_text(text, encoding="utf-8", newline="\n")
    return {"name": n, "bytes": p.stat().st_size, "ok": True, **meta}


def delete_poc(name: str) -> dict:
    if not name_ok(name):
        raise ValueError("模板名不合法")
    p = pocs_dir() / name
    if not p.exists():
        raise FileNotFoundError(name)
    p.unlink()
    return {"name": name}


def split_docs(text: str) -> list[str]:
    """多文档合并粘贴：按 ``---`` 分隔行拆成单条模板。"""
    chunks = re.split(r"(?m)^---[ \t]*$", (text or "").replace("\r\n", "\n"))
    return [c.strip() for c in chunks if c.strip()]


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


def scan_dirs() -> list[str]:
    """nuclei 的 ``-t`` 目录：用户库在前，本机默认模板目录有就一起叠加。"""
    out: list[str] = []
    d = pocs_dir()
    if any(d.glob("*.y*ml")):
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
