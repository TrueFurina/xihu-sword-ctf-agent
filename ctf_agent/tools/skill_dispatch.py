"""Skill 调用入参适配层（2026-10-06）

解决主链断链：`main_agent` 从不 load/调用 skill（详见
logs/mainchain_skill_disconnect_20261006.md）。本模块提供**分派式入参适配**，
让主链能用统一方式调用形态各异的 skill。

## 入参契约实测（scripts/probe_skill_params.py 扫描 11 个已接线 solver）

三类互不兼容：
  A. **文件路径类**（可从题面 attachments 直接喂）：
     - crypto_legendre_phi: path/paths/text/patterns
     - crypto_modinv_factor: path/paths/text/patterns
     - crypto_hastad_broadcast: path/text/patterns/pairs
     - misc_qr_matrix: path/rows/text
     - lfsr_filter_recover: path/text/mask1/mask2/out
  B. **目录类**（需附件所在目录）：
     - crypto_lcg_recover: kind='dir' + dir
  C. **纯数值类**（必须从附件里解析出n/e/ct 等，主链无法凭空构造）：
     - crypto_cycling(n,ct)、crypto_primes_subset(q,x,n,r)、
       crypto_knapsack_mhk(pk,ct)、crypto_electric_mayhem_cls(path)、
       crypto_pkcs1_padding_oracle(c,e)、crypto_complex_mult_group(n,hint,c)

**设计取舍（诚实边界）**：
  - 自动调用**只覆盖 A/B 类**——它们的参数可从题面直接取得，调用是安全的。
  - C 类**不自动调**：参数藏在附件源码里（如 chall.py 的 n/e/ct），主链
    无法可靠解析；宁可不调，也不拿猜测的参数去调 solver（会产生假失败/假水位）。
  - 未在白名单内的 skill 一律不调。
"""
from __future__ import annotations

import os
import re
from typing import Any, Optional

# ── A 类：文件路径类skill（可直接喂题面附件路径）────────────────
_PATH_SKILLS = {
    "crypto_legendre_phi", "crypto_modinv_factor",
    "crypto_hastad_broadcast", "misc_qr_matrix", "lfsr_filter_recover",
}

# ── B 类：目录类 skill（需附件所在目录）─────────────────────────
_DIR_SKILLS = {"crypto_lcg_recover"}

# 允许自动调用的 skill 全集（fail-closed：未列入者一律不调）
AUTO_CALLABLE = _PATH_SKILLS | _DIR_SKILLS

# flag 抽取正则（对齐既有 keyboard_path 分支的思路）
_FLAG_RE = re.compile(rb"(?:flag|FLAG|Flag|ctf|CTF|DASCTF|dasctf)"
                      rb"\{[ -~]{1,200}\}")


def extract_flag(out: Any) -> Optional[str]:
    """从 skill 输出中提取 flag（诚实：提取不到就返回 None，不臆造）。"""
    if out is None:
        return None
    if isinstance(out, (bytes, bytearray)):
        m = _FLAG_RE.search(bytes(out))
        return m.group(0).decode("utf-8", "replace") if m else None
    text = getattr(out, "text", None)
    if text is None:
        text = out if isinstance(out, str) else str(out)
    if isinstance(text, str):
        m = _FLAG_RE.search(text.encode("utf-8", "replace"))
        if m:
            return m.group(0).decode("utf-8", "replace")
    return None


def resolve_first_existing(question: Any) -> Optional[str]:
    """从题面 attachments 里取第一个**真实存在**的附件路径。

    注意：不能按 basename 盲找——全库有 181 道题存在同名附件冲突
    （见logs/truth_consistency_audit_20261006.md），盲找会拿错文件。
    """
    atts = getattr(question, "attachments", None) or []
    if isinstance(atts, str):
        atts = [atts]
    for a in atts:
        p = str(a)
        if os.path.isfile(p):
            return p
    return None


def resolve_attachment_dir(question: Any) -> Optional[str]:
    """取第一个存在附件的**所在目录**（B 类 skill 用）。"""
    p = resolve_first_existing(question)
    if p:
        return os.path.dirname(p)
    return None


def build_params(skill_name: str, question: Any) -> Optional[dict]:
    """按 skill 契约构造 params；无法可靠构造时返回 None（不猜参数）。

    A 类：{"path": 首个存在的附件, "text": 文件内容}
         ——同时给 path 与 text，兼容两种取参风格。
    B 类：{"kind": "dir", "dir": 附件所在目录}
    C 类/未知：None（调用方应跳过）
    """
    if skill_name in _PATH_SKILLS:
        p = resolve_first_existing(question)
        if not p:
            return None
        params = {"path": p}
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                params["text"] = fh.read()
        except OSError:
            pass
        return params
    if skill_name in _DIR_SKILLS:
        d = resolve_attachment_dir(question)
        if not d:
            return None
        return {"kind": "dir", "dir": d}
    return None


def should_auto_call(skill_name: str) -> bool:
    """是否允许主链自动调用该 skill（fail-closed 白名单判定）。"""
    return skill_name in AUTO_CALLABLE
