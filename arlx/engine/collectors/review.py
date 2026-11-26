"""归属审核：一个根域 / 主体到底该不该并进本任务。

以前只有一道 `keep_domain`：只要不在第三方表里就放行，于是小程序包里嵌的高德
SDK、页面里引用的 GitHub 仓库都能被登记成自家根域，后面整片第三方资产跟着进
池。这里把「并线」拆成可解释的三档：

* ``allow``  有规则证据（目标站点本身、同站子域、工商/股权确认的主体、主体名相近）
* ``review`` 规则给不出结论，留给 AI 或人工；**不并线**，避免打偏
* ``deny``   明确是别人的（第三方 SDK / 公共 CDN / 搜索引擎 / 裸 IP）

每个判断都落 ``asset_reviews``，前端按放行 / 待审 / 拒绝三档看，能回答「这条根域
是怎么进来的、为什么没进来」。
"""
from __future__ import annotations

from ...config import config, llm_engine
from ...db import store
from ...utils import ip_host, is_valid_domain, root_domain, same_site
from .. import ai
from . import ownership

# 来源本身就意味着「已确认属于目标」：只做第三方域兜底
TRUSTED_SOURCES = frozenset({
    "target", "domain_target", "input", "seed", "enterprise", "equity", "icp",
    "whois", "asn", "scope", "user",
})
# 从别人的东西里捡到的：必须有同站证据或 AI 认可才并线
WEAK_SOURCES = frozenset({
    "applet", "app", "mobile", "js", "crawl", "leak", "passive", "space", "sdk",
})

SOURCE_LABEL: dict[str, str] = {
    "target": "用户输入", "domain_target": "目标域名", "input": "用户输入", "seed": "种子",
    "enterprise": "工商主体", "equity": "股权子公司", "icp": "备案", "whois": "WHOIS",
    "asn": "ASN", "scope": "任务范围", "user": "手工录入",
    "applet": "小程序", "app": "APP", "mobile": "移动端包", "js": "JS 文件",
    "crawl": "站点爬虫", "leak": "泄露线索", "passive": "被动源", "space": "空间测绘",
    "sdk": "第三方 SDK", "web": "Web 探活", "port": "端口扫描", "dns": "DNS",
    "brute": "字典爆破", "vhost": "VHost 碰撞", "takeover": "子域接管",
    "sibling": "旁站 C 段", "deep": "深度挖掘", "assetdiff": "资产变更",
    "report": "汇总", "ip": "IP 直连",
}

VERDICT_TEXT = {"allow": "放行", "review": "待审", "deny": "拒绝"}


def source_label(source_type: str) -> str:
    return SOURCE_LABEL.get(str(source_type or ""), str(source_type or "未知来源"))


def _affinity(a: str, b: str) -> float:
    """标签相似度：主体名 / 品牌简称在域名里占多大比重。"""
    a = (a or "").lower().strip()
    b = (b or "").lower().strip()
    if not a or not b:
        return 0.0
    if a in b or b in a:
        return 1.0
    best = 0
    for i in range(len(a)):
        for j in range(i + best + 1, len(a) + 1):
            if a[i:j] in b:
                best = max(best, j - i)
    return best / max(1, min(len(a), len(b)))


def rule_verdict(domain: str, *, own_roots=(), targets=(), subject_keys=(),
                 source_type: str = "") -> tuple[str, str]:
    """纯规则判定，返回 ``(verdict, reason)``；不发网络请求。"""
    d = (domain or "").strip().lower().strip(".")
    if not d:
        return "deny", "空域名"
    if ip_host(d):
        return "deny", "裸 IP 不能当根域"
    if d.count(":") == 1 and d.rsplit(":", 1)[1].isdigit():
        d = d.rsplit(":", 1)[0]
    r = (root_domain(d) or d).lower()
    if ip_host(r):
        return "deny", "裸 IP 不能当根域"
    if ownership.is_non_domain(d):
        return "deny", "不是合法域名"
    own = {str(x).strip().lower() for x in (own_roots or ()) if str(x or "").strip()}
    for o in own:
        if d == o or d.endswith("." + o):
            return "allow", "已在目标池"
    tag = ownership.foreign_label(d)
    if tag:
        return "deny", f"第三方资源（{tag}），不属于目标主体"
    tgt = {str(x).strip().lower() for x in (targets or ()) if str(x or "").strip()}
    # 目标里可能混着企业名，只拿域名形态的比对
    tgt = {t for t in tgt if is_valid_domain(t)}
    if tgt and any(same_site(d, t) or same_site(r, t) for t in tgt):
        return "allow", "与目标站点同域"
    if source_type in TRUSTED_SOURCES:
        return "allow", f"来源可信（{source_label(source_type)}）"
    for k in subject_keys or ():
        k = str(k or "").strip()
        if len(k) < 2:
            continue
        if k.lower() in d or _affinity(k, r.split(".")[0]) >= 0.6:
            return "allow", f"与主体名「{k}」相近"
    return "review", f"来源为{source_label(source_type)}，规则无法认定归属"


async def ai_judge(target: str, items: list[tuple[str, str, str]]) -> dict[str, tuple[str, str]]:
    """AI 批量复核待审域名：``[(域名, 来源类型, 出处)]`` → ``{域名: (verdict, reason)}``。"""
    if not items or not llm_engine():
        return {}
    names: list[str] = []
    for d, _st, _su in items:
        if d not in names:
            names.append(d)
    names = names[:15]
    hints = "；".join(f"{d}（出现在{source_label(st)}）" for d, st, _su in items[:15]
                     if d in names)
    try:
        got = await ai.judge_domains(target, names, notes_hint=hints)
    except Exception:
        return {}
    out: dict[str, tuple[str, str]] = {}
    for item in got.items():
        key = str(item[0] or "").strip().lower()
        info = item[1] or {}
        verdict = "allow" if info.get("belong") is True else "deny"
        why = str(info.get("why") or "").strip()
        reason = f"AI 复核：{why or ('属于目标主体' if verdict == 'allow' else '不属于目标主体')}"
        for name in names:
            if name == key or name.endswith("." + key) or key.endswith("." + name):
                out[name] = (verdict, reason)
    return out


class Reviewer:
    """带缓存与落库的审核器；一个任务一个实例。"""

    def __init__(self, task_id: str, target: str, *, own_roots=None, targets=None,
                 subject_keys=None, ratio: float = 100.0, enabled: bool = True,
                 ai_enabled: bool | None = None, log=None) -> None:
        self.task_id = task_id
        self.target = target
        self.own_roots = set(own_roots or ())
        self.targets = set(targets or ())
        self.subject_keys = {str(k) for k in (subject_keys or ()) if str(k or "").strip()}
        self.ratio = float(ratio or 0)
        self.enabled = bool(enabled)
        self.ai_enabled = bool(config.get("scan", "ai_review", default=True)
                               if ai_enabled is None else ai_enabled)
        self._log = log
        self.cache: dict[str, dict] = {}

    def sync(self, *, own_roots=None, targets=None, subject_keys=None) -> None:
        """跟着任务进度刷新比对基准：目标池会长、主体名会变。"""
        self.own_roots = set(own_roots or ())
        self.targets = set(targets or ())
        self.subject_keys = {str(k) for k in (subject_keys or ()) if str(k or "").strip()}

    # ── 同步规则判定（claim_root 里用） ──
    def assess(self, subject: str, *, source_type: str = "", source_url: str = "",
               stage: str = "", kind: str = "root", persist: bool = True) -> dict:
        key = (subject or "").strip().lower()
        if not key:
            return {"subject": key, "verdict": "deny", "reason": "空域名", "engine": "rule"}
        rec = self.cache.get(key)
        # 早先被判成待审 / 拒绝的，后来又有了可信来源（工商、股权、域名目标），
        # 按新证据重判一次；否则先被爬虫顺手带出来一次就把正经根域永久挡住了。
        if rec and rec.get("verdict") != "allow" and source_type in TRUSTED_SOURCES:
            rec = None
        if rec:
            return rec
        verdict, reason = rule_verdict(key, own_roots=self.own_roots, targets=self.targets,
                                       subject_keys=self.subject_keys,
                                       source_type=source_type)
        if not self.enabled and verdict == "review":
            # 审核关掉只是不再拦「说不清归属」的域名；第三方 SDK / 公共站这类
            # 明确是别人的东西照旧拒绝，否则打偏的问题会立刻回来。
            verdict, reason = "allow", "归属审核已关闭，非第三方资源"
        rec = {"subject": key, "verdict": verdict, "reason": reason, "engine": "rule"}
        rec["source_type"] = source_type
        rec["source_url"] = source_url
        self.cache[key] = rec
        if persist:
            self._persist(rec, source_type=source_type, source_url=source_url,
                          stage=stage, kind=kind)
        return rec

    # ── 异步批量复核（阶段里在并线前调） ──
    async def review(self, items: list[dict], *, stage: str = "") -> dict[str, dict]:
        """``items`` 每项 ``{subject, source_type, source_url}``；返回 ``{域名: 结论}``。"""
        out: dict[str, dict] = {}
        pending: list[dict] = []
        for it in items or ():
            key = str(it.get("subject") or "").strip().lower()
            if not key:
                continue
            rec = self.assess(key, source_type=str(it.get("source_type") or ""),
                              source_url=str(it.get("source_url") or ""), stage=stage,
                              kind=str(it.get("kind") or "root"), persist=False)
            out[key] = rec
            if rec["verdict"] == "review" and self.ai_enabled:
                pending.append({**it, "subject": key})
        if not pending:
            for rec in out.values():
                self._persist(rec, source_type=rec.get("source_type", ""), stage=stage,
                              source_url=rec.get("source_url", ""))
            return out
        judged = await ai_judge(self.target, [
            (p["subject"], str(p.get("source_type") or ""), str(p.get("source_url") or ""))
            for p in pending])
        ai_used = bool(judged)
        for p in pending:
            key = p["subject"]
            if key in judged:
                verdict, reason = judged[key]
                old = out.get(key, {})
                rec = {"subject": key, "verdict": verdict, "reason": reason, "engine": "ai",
                       "source_type": old.get("source_type", ""),
                       "source_url": old.get("source_url", "")}
                self.cache[key] = rec
                out[key] = rec
        for rec in out.values():
            self._persist(rec, source_type=rec.get("source_type", ""), stage=stage,
                          source_url=rec.get("source_url", ""))
        if ai_used and self._log:
            left = sum(1 for r in out.values() if r["verdict"] == "review")
            self._log("review", f"AI 复核 {len(judged)} 个域名，仍有 {left} 个待人工确认")
        return out

    def _persist(self, rec: dict, *, source_type: str = "", source_url: str = "",
                 stage: str = "", kind: str = "root") -> None:
        try:
            store.add_review(
                self.task_id, stage=stage, kind=kind, subject=rec.get("subject", ""),
                target=self.target, verdict=str(rec.get("verdict") or "review"),
                reason=str(rec.get("reason") or ""), engine=str(rec.get("engine") or "rule"),
                ratio=self.ratio, source_type=source_type, source_url=source_url,
            )
        except Exception:
            pass
