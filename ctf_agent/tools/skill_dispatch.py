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
  - A/B 类（路径/目录）：参数天然安全，**总是能构造** → 自动调。
  - C 类（纯数值）：2026-10-07 起，参数若能以**结构化方式确定性解析**
    （AST / ast.literal_eval / 带门限的正则）才自动调，见 _NUMERIC_EXTRACTORS；
    **参数到齐才产出**，缺一个即 None——宁可不调，也不拿猜测的参数去调
    solver（会产生假失败/假水位）。当前接入 cycling / primes_subset / knapsack_mhk。
    electric-mayhem-cls 的 .tgz/.gz 与 pkcs1_padding_oracle 的多阶段编排不在此列。
  - 未在白名单内的 skill 一律不调。
"""
from __future__ import annotations

import ast
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

# ── C 类：纯数值类 skill（2026-10-07 新增，参数需从附件静态解析）──
# 见下方 _NUMERIC_EXTRACTORS：**提取成功且完整性校验通过**才产出 params。
_NUMERIC_SKILLS = {
    "crypto_cycling", "crypto_primes_subset", "crypto_knapsack_mhk",
}

# 允许自动调用的 skill 全集（fail-closed：未列入者一律不调）
AUTO_CALLABLE = _PATH_SKILLS | _DIR_SKILLS | _NUMERIC_SKILLS

# flag 抽取正则（对齐既有 keyboard_path 分支的思路）
# 2026-10-07 修复**抽取过度**（真实缺陷，由 Cycling 端到端实证发现）：
#   原正则 `{[ -~]{1,200}` 是**贪婪**的，而多数 skill 返回 Python dict 的 repr，
#   例如 ``{'flag': 'CTF{Recycling_Is_Great}'}`` —— 正则一路吃到**最外层**的
#   ``}`` 之后还剩一个 ``'}`` 尾巴，于是抽出 ``CTF{Recycling_Is_Great}'}``。
#   结果是「solver 明明解对了，却提交了带杂质尾缀的错误 flag」，评分取 sha256
#   比对 → 本该得分的题判失败。改为**非贪婪**到第一个 ``}`` 即止。
# 取最短闭合的代价：flag 内部若含 ``}`` 会被截断——CTF flag 惯例不含该系统性
#   风险远低于贪婪版本必错的尾缀污染。
_FLAG_RE = re.compile(rb"(?:flag|FLAG|Flag|ctf|CTF|DASCTF|dasctf)"
                      rb"\{[ -~]{1,200}?\}")


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

    A 类：{"path": 单个附件路径, "text": 其内容}——**单个**，不合并。
         ⚠️ 实测教训（2026-10-06）：不能无脑取「第一个存在的附件」——
            ezRSA 有两个附件（task.py 加密脚本 + output 数据文件），
            取第一个喂给 skill 会返回 None（解不出），而 output 才能解出。
            故本函数只保证「至少有一个可试的路径」，由调用方
            （skill_dispatch.iter_candidate_params）逐个试探。
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
    if skill_name in _NUMERIC_SKILLS:
        # C 类：走确定性提取器，参数不全返回 None（绝不拿猜测值喂 solver）
        return extract_numeric_params(skill_name, question)
    return None


def iter_candidate_params(skill_name: str, question: Any):
    """产出该 skill 可尝试的 params 序列（按附件顺序，含目录兜底）。

    修「多附件题只试第一个」的缺陷：ezRSA 的 task.py 解不出、output 能解出，
    故必须逐个附件试探。目录类 skill 只有一个候选。
    C 类（数值）走 _NUMERIC_EXTRACTORS：产出**至多一个**已通过完整性校验的
    params；提取不出就一个都不产出（不猜参数）。
    """
    if skill_name in _NUMERIC_SKILLS:
        p = build_params(skill_name, question)
        if p:
            yield p
        return
    # ⚠️ 2026-10-07 修复：本分支曾被一次误编辑**整体覆盖删除**（把下面的 _DIR
    # 分支片段替换成了上面的 _NUMERIC 片段），导致唯一的 B 类目录 skill
    # crypto_lcg_recover 在主链里走到 ``not in _PATH_SKILLS`` → return，
    # **永远不被调用**，且当时无任何测试覆盖 iter_candidate_params 的目录分支
    # （只测了 build_params），故 1157 个用例全绿也没拦住。恢复 + 补测试。
    if skill_name in _DIR_SKILLS:
        p = build_params(skill_name, question)
        if p:
            yield p
        return
    if skill_name not in _PATH_SKILLS:
        return
    atts = getattr(question, "attachments", None) or []
    if isinstance(atts, str):
        atts = [atts]
    n = 0
    for a in atts:
        p = str(a)
        if not os.path.isfile(p):
            continue
        n += 1
        params = {"path": p}
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                params["text"] = fh.read()
        except OSError:
            pass
        yield params
    if n == 0:  # 附件路径都不可直接用时，退回首个存在的（可能为相对根差异）
        p = build_params(skill_name, question)
        if p:
            yield p


# ── C 类：确定性参数提取器（2026-10-07）────────────────────────
# 设计纪律（与 A/B 类的区别就在这里）：
#   A/B 类只喂「文件/目录路径」，路径天然安全、不会猜错值；
#   C 类要喂**数值**，猜错就会产生「假失败」甚至「假成功」，所以必须：
#     ① 用**结构化解析**（AST / literal_eval / 带门限的正则）而非模糊匹配；
#     ② 参数**全部到齐**才产出 params（缺一个即 None）；
#     ③ 产出前做**完整性校验**（类型/量级/长度合理性）；
#     ④ 解析不了就说解析不了——绝不用默认值去糊弄 solver。
_MAX_TEXT_BYTES = 1 << 20  # 单附件最多读 1MB：防止把 .tgz/.gz 二进制灌进正则


def iter_attachment_texts(question: Any):
    """产出 (path, text) —— 仅真存在且可读的文本附件。

    跳过：不存在的路径、二进制（解码异常）、超过 _MAX_TEXT_BYTES 的大文件。
    electric-mayhem-cls 的 elmo.tgz / stm32f0_aes.json.gz 在此被排除——它们是
    打包/压缩数据，需先解包预处理，不属本层的确定性提取范围。
    """
    atts = getattr(question, "attachments", None) or []
    if isinstance(atts, str):
        atts = [atts]
    for a in atts:
        p = str(a)
        if not os.path.isfile(p):
            continue
        try:
            if os.path.getsize(p) > _MAX_TEXT_BYTES:
                continue
            with open(p, "r", encoding="utf-8", errors="strict") as fh:
                yield p, fh.read()
        except (OSError, UnicodeDecodeError, ValueError):
            continue


def _extract_cycling(texts) -> Optional[dict]:
    """Google CTF 2022 Cycling：chall.py 里的 ``n``/``ct``（0x 长十六进制）。

    门限 ≥40 位十六进制：chall.py 同文件里还有多个**样例短值**
    （如 0x112b00148621），不过滤会把样例当真值喂进 solver。
    """
    for _p, t in texts:
        n = re.search(r"\bn\s*=\s*(0x[0-9a-fA-F]{40,})", t)
        ct = re.search(r"\bct\s*=\s*(0x[0-9a-fA-F]{40,})", t)
        if not (n and ct):
            continue
        params = {"n": n.group(1), "ct": ct.group(1)}
        e = re.search(r"\be\s*=\s*(\d{1,10})\b", t)
        if e:
            params["e"] = int(e.group(1))
        return params
    return None


def _extract_primes(texts) -> Optional[dict]:
    """Google CTF 2023 Primes：注释里的官方输出 ``q = 0x..`` / ``x = 0x..``。

    ``n``（flag 的比特总数 = 7·len(flag)）**不在题面显式给出**，但可由
    ``m = b"..."`` 的行长度推出（7 bit/字符）；要求 n ≥ r 且 7 | n 才采信。
    ⚠️ 该 m 是题目自带的示例明文；其**长度**用于定 n（布局参数），
    其**内容**不可当 flag——真值仍由 solver 从 (q,x,n) 解出。
    """
    for _p, t in texts:
        q = re.search(r"\bq\s*=\s*(0x[0-9A-Fa-f]{16,})", t)
        x = re.search(r"\bx\s*=\s*(0x[0-9A-Fa-f]{16,})", t)
        m = re.search(r'\bm\s*=\s*b"([^"\n]*)"', t)
        if not (q and x and m):
            continue
        try:
            n_bits = 7 * len(m.group(1).encode("utf-8", "surrogateescape"))
        except Exception:  # noqa: BLE001
            continue
        if n_bits == 0 or n_bits % 7 != 0 or n_bits < 131:
            continue  # 完整性校验不通过 → 不用猜的值去喂 solver
        return {"kind": "solve", "q": q.group(1), "x": x.group(1),
                "n": n_bits, "r": 131}
    return None


def _extract_mhk2(texts) -> Optional[dict]:
    """Google CTF 2023 MHK2：output.txt 两行——公钥 dict + 密文 tuple 列表。

    逐行 ``ast.literal_eval``：dict 行含 a1/a2 即 pk；全是二元 tuple 的 list 即 ct。
    两者都拿到才产出，缺一即 None（避免用残缺 pk 做昂贵且必失败的格攻击）。
    """
    for _p, t in texts:
        pk = None
        ct = None
        for line in t.splitlines():
            line = line.strip()
            if not line or len(line) > _MAX_TEXT_BYTES:
                continue
            try:
                v = ast.literal_eval(line)
            except (ValueError, SyntaxError, MemoryError, RecursionError):
                continue
            if isinstance(v, dict) and "a1" in v and "a2" in v:
                if isinstance(v["a1"], list) and isinstance(v["a2"], list):
                    pk = {"a1": v["a1"], "a2": v["a2"]}
            elif (isinstance(v, list) and v
                  and isinstance(v[0], (tuple, list)) and len(v[0]) == 2):
                ct = v
        if pk and ct:
            return {"kind": "mhk2_decrypt", "pk": pk, "ct": ct}
    return None


# 显式注册表（fail-closed：未登记的 C 类 skill 不自动调）
_NUMERIC_EXTRACTORS = {
    "crypto_cycling": _extract_cycling,
    "crypto_primes_subset": _extract_primes,
    "crypto_knapsack_mhk": _extract_mhk2,
}


def extract_numeric_params(skill_name: str, question: Any) -> Optional[dict]:
    """C 类统一入口：提取成功→params dict；否则 None（可供测试直接断言）。"""
    fn = _NUMERIC_EXTRACTORS.get(skill_name)
    if fn is None:
        return None
    try:
        params = fn(iter_attachment_texts(question))
    except Exception:  # noqa: BLE001 - 任何解析异常一律视为「提取失败」
        return None
    return params if isinstance(params, dict) and params else None


def should_auto_call(skill_name: str) -> bool:
    """是否允许主链自动调用该 skill（fail-closed 白名单判定）。"""
    return skill_name in AUTO_CALLABLE
