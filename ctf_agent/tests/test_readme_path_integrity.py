# -*- coding: utf-8 -*-
"""README 路径完整性（两套基准）——防"文档提到一个不存在 / 被发布树剔除的文件"。

背景（2026-09-19）：`deliverables/复盘赛报/` 14 篇全文入库后，README 指向的文件越来越多，
而此前**没有任何机器**在防"文档提到一个不存在/已被排除的文件"。转公开后死链直接伤害
"可核验"这个卖点。本闸门把 README 里每一个像路径的 token 都拿去和 `git ls-files` +
`release_export.py` 的发布树剔除名单对照。

═══════════════════════════ 判定口径（勿擅自放宽）═══════════════════════════
1. 来源：两份 README 里**反引号包裹的行内代码**与 **markdown 链接**中的路径 token。
   先剔除 ``` 围栏代码块（那是 ASCII 树状图，不是引用）。
2. **两套基准，缺一不可**（PM 提出）：
   - 行内代码 → 基准 `ctf_agent/`，不命中再**回退仓库根**
   - markdown 链接 `[text](target)` → 基准 = 该 README 所在目录（仓库根）
   ⚠️ 单一基准会把 `[MIT](LICENSE)` 解析成 `ctf_agent/LICENSE` → 假红；然后有人"为了修红"
   去改 README，把一个正确的链接改坏。**闸门第一要务是先不误伤正确写法**（见
   test_code_span_base_is_ctf_agent_and_link_base_is_root）。
3. **存活定义（两条都要判）**：路径在 HEAD 树内存在 **且** 不落在 `release_export.py`
   的 `EXCLUDE_DIRS` / `EXCLUDE_FILES` 里。只判"被跟踪"不够——发布树还会剔除一批。
4. glob：`scripts/verify_*.py`、`data/questions_real/**` 这类要能匹配；
   **glob 命中数为 0 必须判失败**（见 test_glob_zero_match_is_violation）。
5. 例外：**逐条给理由**。
   - `ALLOWLIST` = README **故意提到但确实不在发布树里**的路径（在陈述"我们不包含它"），合法。
   - `KNOWN_DEFECTS` = **真实缺陷**（README 指向了不存在/未入库的文件），**已上报 team-lead**，
     仅作为过渡存在；由 `test_known_defects_are_still_broken` 保证它**自毁**
     ——一旦有人修好，该测试立刻变红，逼你把条目从列表里删掉，不许静默常驻。
6. fail-closed：解析不到 token / git 列表拿不到 / 文件读不到 → 判失败，绝不静默通过。
═══════════════════════════════════════════════════════════════════════════
"""
from __future__ import annotations

import fnmatch
import os
import re
import subprocess
import sys

import pytest

_AGENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ROOT = os.path.dirname(_AGENT)
if _AGENT not in sys.path:
    sys.path.insert(0, _AGENT)

import scripts.release_export as rel  # noqa: E402

README_EN = os.path.join(_ROOT, "README.md")
README_ZH = os.path.join(_ROOT, "README.zh.md")

# 围栏代码块（ASCII 架构图）不是引用，先剔除（保留行数以便行号对齐）
_FENCE_RE = re.compile(r"^```.*?^```", re.S | re.M)
# markdown 链接
_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
# 行内代码
_SPAN_RE = re.compile(r"`([^`\n]+)`")
# 形态像路径：允许字母/数字/_ . - / * 与中文（本仓库文件名含中文），首字符须为字母/数字/中文/_/-
_PATHY_RE = re.compile(r"^[A-Za-z0-9_\u4e00-\u9fff\-][A-Za-z0-9_.\-/*\u4e00-\u9fff]*$")
_HAS_LETTER_RE = re.compile(r"[A-Za-z\u4e00-\u9fff]")
_EXTS = (".py", ".md", ".sh", ".json", ".yml", ".yaml", ".txt", ".ini", ".toml",
         ".php", ".png", ".zip", ".log", ".csv", ".cfg", ".js", ".html")

# ───────────────────────── 例外：合法（陈述"我们不包含它"） ─────────────────────────
# 每条必须写明理由；由 test_allowlist_entries_still_absent 防止条目失效后赖着不走。
ALLOWLIST: dict[str, str] = {
    "data/race_details/": "README.md:102/zh:94 明确陈述「内部赛事资源（data/race_details/、附件、签名）"
                          "经 .gitignore 排除」——是在说明**不收录**，不是引用",
    "flag.txt": "README.md:100/zh:92 陈述「仅原始明文 flag.txt/flag.png 被 .gitignore 排除」——在说明**不收录**",
    "flag.png": "同上（flag.png 与 flag.txt 同句并列）",
    "index.php": "README.md:84/zh:84 描述**题面自带**的文件（real_web_gongye_web2 的 flag 在它提供的 index.php 里）"
                 "，不是仓库路径",
}


def _allow_key(token: str) -> str:
    """例外表键归一化：目录尾斜杠不参与匹配（README 里 `data/race_details/` 带尾斜杠）。"""
    return token.rstrip("/") if token.endswith("/") else token


# ───────────────────── 已知缺陷（已上报 team-lead，过渡条目，自毁） ─────────────────────
# ⚠️ 这三处是 README **真实指向了不存在/未入库的文件**，不是 allowlist 式"合法例外"。
# 已上报 team-lead（2026-09-19）。修好后 test_known_defects_are_still_broken 会变红，
# 必须从本字典删除，不许静默常驻。
KNOWN_DEFECTS: dict[str, str] = {
    "data/results/CTF-Agent深度评审报告_20260828.md":
        "README.md:86 引用；该文件既未被 git 跟踪（data/results/*.md 在 .gitignore），"
        "又落在 EXCLUDE_DIRS=ctf_agent/data/results 内 → 发布树里没有它。待 README 改引已入库证据或补证据文件",
    "deliverables/benchmark_runs/llm_breaking_ice_20260901-050201.json":
        "README.md:88/90 引用为 11/15 的 disk truth；文件在磁盘上但**未入库**（同目录 2026-08-28 的四份已入库）"
        "→ 读者无法核验。待补 git add 或改引已入库报告",
    "MEMORY.md":
        "README.md:92 引用「Details in MEMORY.md」；该文件在仓库内外均不存在（git ls-files 与磁盘都查无）"
        "→ 纯死链。待 README 删除该引用或补文件",
}

# 归一化后的例外键集合（两张表的键都可能带目录尾斜杠）
_ALLOW_KEYS = {_allow_key(k): v for k, v in ALLOWLIST.items()}
_KNOWN_KEYS = {_allow_key(k): v for k, v in KNOWN_DEFECTS.items()}


def _is_exception(token: str) -> bool:
    """是否为书面例外（合法 allowlist 或已上报的已知缺陷）。"""
    k = _allow_key(token)
    return k in _ALLOW_KEYS or k in _KNOWN_KEYS


@pytest.fixture(scope="module")
def tracked() -> list[str]:
    """HEAD 树内的全部跟踪路径（仓库根相对）。拿不到 → fail-closed 直接失败。"""
    r = subprocess.run(["git", "ls-files", "-z"], cwd=_ROOT, capture_output=True,
                       text=True, encoding="utf-8", errors="replace", timeout=300)
    assert r.returncode == 0, f"git ls-files 失败（fail-closed，不得静默通过）: {r.stderr}"
    paths = [p for p in r.stdout.split("\0") if p]
    assert len(paths) > 100, f"跟踪文件数异常少（{len(paths)}），拒绝判定"
    return paths


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _strip_fences(text: str) -> str:
    """剔除 ``` 围栏块，保留行数以便行号对齐。"""
    return _FENCE_RE.sub(lambda m: "\n" * m.group(0).count("\n"), text)


def _line_of(text: str, off: int) -> int:
    return text[:off].count("\n") + 1


def _alive(rel_path: str, tracked_paths: list[str]) -> tuple[bool, str]:
    """存活判定（仓库根相对路径）。返回 (是否命中, 原因)。"""
    rp = rel_path[2:] if rel_path.startswith("./") else rel_path
    if rp in tracked_paths:
        return True, "file"
    if any(p.startswith(rp.rstrip("/") + "/") for p in tracked_paths):
        return True, "dir"
    if any(ch in rp for ch in "*?["):
        n = sum(1 for p in tracked_paths if fnmatch.fnmatch(p, rp))
        return (True, f"glob({n})") if n else (False, "glob命中0")
    return False, "不存在"


def _is_excluded(rel_path: str, exclude_dirs, exclude_files) -> bool:
    rp = rel_path[2:] if rel_path.startswith("./") else rel_path
    if rp in exclude_files:
        return True
    return any(rp == d or rp.startswith(d + "/") for d in exclude_dirs)


def _unique_basename(token: str, tracked_paths: list[str]) -> tuple[bool, str]:
    """裸文件名（无目录分隔符）的宽容解析：仓库内**唯一**同名文件时接受。

    为什么需要这条（否则会假红并诱使有人去改正确的 README）：README 散文里常把前面已给全路径的
    文件再以裸文件名复述，如 `scripts/verify_10732.py` + `verify_10735.py` + `verify_specialcurve2.py`。
    这些文件在仓库里唯一存在。严格按"基准 ctf_agent/ + 回退根"两档解析会把它们判死，
    那才是假红。故：无目录分隔符且两档都不命中时，允许按**唯一 basename** 解析；
    不唯一或不存在 → 仍然判失败（所以 MEMORY.md 这种真死链照样红）。
    """
    hits = [p for p in tracked_paths if os.path.basename(p) == token]
    if len(hits) == 1:
        return True, f"唯一basename({hits[0]})"
    if len(hits) > 1:
        return False, f"basename歧义({len(hits)}处)"
    return False, "不存在"


def _span_candidates(token: str) -> list[str]:
    """行内代码基准 ctf_agent/，再回退仓库根。"""
    t = token[2:] if token.startswith("./") else token
    if t.startswith("ctf_agent/"):
        return [t]
    return [f"ctf_agent/{t}", t]


def collect_violations(text: str, tracked_paths: list[str], exclude_dirs=None,
                       exclude_files=None) -> tuple[list[dict], int]:
    """扫描一份 README 文本。返回 (违规列表, 解析到的 token 数)。

    违规 = 既不在 HEAD 树内（或被发布树剔除），又不在 ALLOWLIST / KNOWN_DEFECTS 里。
    """
    exclude_dirs = list(rel.EXCLUDE_DIRS) if exclude_dirs is None else list(exclude_dirs)
    exclude_files = list(rel.EXCLUDE_FILES) if exclude_files is None else list(exclude_files)
    body = _strip_fences(text)
    violations: list[dict] = []
    n_tokens = 0

    # ── markdown 链接：基准 = README 所在目录（仓库根），不回退 ctf_agent/ ──
    for m in _LINK_RE.finditer(body):
        target = m.group(1)
        if target.startswith(("http://", "https://", "mailto:", "tel:", "#")):
            continue
        rel_path = target[2:] if target.startswith("./") else target
        if not _PATHY_RE.match(rel_path):
            continue
        n_tokens += 1
        ok, why = _alive(rel_path, tracked_paths)
        if ok and _is_excluded(rel_path, exclude_dirs, exclude_files):
            ok, why = False, f"被发布树剔除({rel_path})"
        if not ok and not _is_exception(rel_path):
            violations.append({"kind": "link", "token": target, "rel": rel_path,
                               "why": why, "line": _line_of(body, m.start())})

    # ── 行内代码：基准 ctf_agent/，回退仓库根，裸文件名走唯一 basename ──
    for m in _SPAN_RE.finditer(body):
        tok = m.group(1).strip()
        if " " in tok or not _PATHY_RE.match(tok) or not _HAS_LETTER_RE.search(tok):
            continue
        if "<" in tok or "(" in tok or tok.startswith("$"):
            continue
        if "/" not in tok and not tok.endswith(_EXTS):
            continue
        n_tokens += 1
        ok, why = False, "未解析"
        # 首个命中的候选即定案（不可被后续候选覆盖）：
        # 否则 ctf_agent/… 命中但被发布树剔除时，回退档再用"不存在"把"被剔除"这个结论冲掉。
        for cand in _span_candidates(tok):
            hit, detail = _alive(cand, tracked_paths)
            if hit:
                if _is_excluded(cand, exclude_dirs, exclude_files):
                    ok, why = False, f"被发布树剔除({cand})"
                else:
                    ok, why = True, f"{cand}:{detail}"
                break
        if not ok and why == "未解析":
            # 两档都没命中：保留首档的具体原因（glob 命中 0 与"不存在"要能区分）
            why = _alive(_span_candidates(tok)[0], tracked_paths)[1]
        if not ok and "/" not in tok:
            ok2, why2 = _unique_basename(tok, tracked_paths)
            if ok2:
                ok, why = True, why2
        if not ok and not _is_exception(tok):
            violations.append({"kind": "span", "token": tok, "rel": tok,
                               "why": why, "line": _line_of(body, m.start())})
    return violations, n_tokens


def _fmt(v: dict) -> str:
    return f"  - [{v['kind']}] L{v['line']} `{v['token']}` → {v['why']}"


# ══════════════════════════════ 主闸门 ══════════════════════════════

@pytest.mark.parametrize("readme", ["README.md", "README.zh.md"])
def test_no_dead_path_references(tracked, readme):
    """README 里每一个路径 token 都必须在 HEAD 树内 且 不被发布树剔除。"""
    text = _read(os.path.join(_ROOT, readme))
    v, n = collect_violations(text, tracked)
    assert n >= 10, f"{readme} 只解析到 {n} 个路径 token（应 >=10）——解析器可能失效，fail-closed"
    assert not v, (f"{readme} 存在 {len(v)} 处死链/被剔除引用：\n"
                   + "\n".join(_fmt(x) for x in v)
                   + "\n处置：改 README 指向真实文件；或若在陈述「我们不包含它」，"
                     "把该路径加入 ALLOWLIST **并写明理由**；真缺陷请进 KNOWN_DEFECTS 并上报")


# ══════════════════════════ 两套基准（防误伤） ══════════════════════════

def test_code_span_base_is_ctf_agent_and_link_base_is_root(tracked):
    """① `LICENSE`（行内代码）判存在；② [MIT](LICENSE)（链接）判存在。

    这两条是"先不误伤正确写法"的钉子：单一基准会把 LICENSE 解析成 ctf_agent/LICENSE
    → 假红 → 诱使有人去改一个本来正确的 README。
    """
    exists_anywhere = os.path.exists(os.path.join(_ROOT, "LICENSE"))
    assert exists_anywhere, "仓库根 LICENSE 应存在"

    # ① 行内代码：先试 ctf_agent/…（可能不存在），回退仓库根必须命中
    span_cands = _span_candidates("LICENSE")
    assert span_cands[0] == "ctf_agent/LICENSE", "行内代码首基准必须是 ctf_agent/"
    assert any(_alive(c, tracked)[0] for c in span_cands), \
        "`LICENSE` 作为行内代码应在两档基准之一命中（仓库根回退）"

    # ② 链接：基准是 README 所在目录（仓库根），不得被解析到 ctf_agent/ 下
    link_text = "[MIT](LICENSE)\n"
    v, n = collect_violations(link_text, tracked)
    assert n == 1, f"[MIT](LICENSE) 应被解析为 1 个 token，实际 {n}"
    assert not v, f"[MIT](LICENSE) 是正确写法，不得判红：{v}"


def test_link_is_not_resolved_under_ctf_agent(tracked):
    """链接基准只能是仓库根：一个只在 ctf_agent/ 下存在的文件，用链接形式引用必须判红。"""
    # 挑一个"只在 ctf_agent/ 下存在、仓库根没有同名文件"的文件（否则链接基准也能命中，用例失效）
    tok = None
    for p in tracked:
        if not (p.startswith("ctf_agent/") and p.count("/") == 1):
            continue
        base = p[len("ctf_agent/"):]
        if _alive(base, tracked)[0] or _is_exception(base):
            continue
        tok = base
        break
    assert tok, "应能找到只在 ctf_agent/ 下存在的文件"
    v, n = collect_violations(f"[x](./{tok})\n", tracked)
    assert n == 1
    assert v and v[0]["kind"] == "link", \
        f"链接基准必须是仓库根：{tok} 只在 ctf_agent/ 下存在，链接形式应判红（否则两套基准退化成一档）"


# ══════════════════════════════ glob 支持 ══════════════════════════════

def test_glob_zero_match_is_violation(tracked):
    """glob 能匹配要放行；glob 命中数为 0 必须判失败。"""
    ok_v, n = collect_violations("见 `scripts/verify_*.py` 与 `data/questions_real/**`\n", tracked)
    assert n == 2
    assert not ok_v, f"能匹配的 glob 应放行：{[_fmt(x) for x in ok_v]}"

    bad_v, n2 = collect_violations("见 `scripts/definitely_not_here_*.py`\n", tracked)
    assert n2 == 1
    assert bad_v and "glob命中0" in bad_v[0]["why"], \
        f"glob 命中 0 必须判失败，实际 {bad_v}"


def test_existing_glob_patterns_in_readme_are_accepted(tracked):
    """README 里真实使用的 glob（`data/questions_real/**`）必须放行。"""
    v, n = collect_violations(_read(README_EN), tracked)
    assert any(x["token"] == "data/questions_real/**" for x in v) is False, \
        "README 里的 `data/questions_real/**` 必须能匹配（glob 支持）"


# ══════════════════════════ 变异验证（三次都变红） ══════════════════════════

def test_mutation_nonexistent_path_must_be_flagged(tracked):
    """变异一：插一句引用**不存在**的文件 → 必须变红。"""
    text = _read(README_EN) + "\n参考 `scripts/definitely_not_here.py` 里的实现。\n"
    v, _ = collect_violations(text, tracked)
    assert any(x["token"] == "scripts/definitely_not_here.py" for x in v), \
        f"引用不存在的文件必须判红，实际违规={[_fmt(x) for x in v]}"


def test_mutation_excluded_real_path_must_be_flagged(tracked):
    """变异二：插一句引用**被 EXCLUDE_DIRS 排除的真实路径** → 必须变红。

    注意：这个路径确实被 git 跟踪（只判"被跟踪"会漏），但发布树会剔除它。
    """
    sample = None
    for d in rel.EXCLUDE_DIRS:
        hits = [p for p in tracked if p.startswith(d + "/")]
        if hits:
            sample = (d, hits[0])
            break
    assert sample, "EXCLUDE_DIRS 里应至少有一个含被跟踪文件的目录（否则本用例无法证明第 3 条）"
    d, hit = sample
    tok = hit[len("ctf_agent/"):] if hit.startswith("ctf_agent/") else hit
    text = _read(README_EN) + f"\n详见 `{tok}`。\n"
    v, _ = collect_violations(text, tracked)
    flagged = [x for x in v if x["token"] == tok]
    assert flagged, f"{tok} 落在 EXCLUDE_DIRS={d} 内，必须判红（实际未判红）"
    assert "剔除" in flagged[0]["why"], f"失败原因必须写明是被发布树剔除：{flagged[0]['why']}"


def test_mutation_adding_exclude_dir_flips_readme_to_red(tracked, monkeypatch):
    """变异三：往 EXCLUDE_DIRS 加一个 README 会提到的目录 → 必须变红。

    证明闸门与 `release_export.py` 的实现是**真耦合**，不是把剔除名单硬编码抄了一份。
    """
    v0, _ = collect_violations(_read(README_EN), tracked)
    assert not v0, "基线应先是绿的，否则本变异无意义"

    monkeypatch.setattr(rel, "EXCLUDE_DIRS", list(rel.EXCLUDE_DIRS) + ["ctf_agent/skills"])
    v, _ = collect_violations(_read(README_EN), tracked)
    assert v, "把 ctf_agent/skills 加入 EXCLUDE_DIRS 后，README（引用 skills/ 与 skills/*.py）应立刻变红"
    assert any("skill" in x["token"] for x in v), f"变红项应来自 skills 相关引用：{[_fmt(x) for x in v]}"


# ══════════════════════════ 例外列表的自毁机制 ══════════════════════════

def test_known_defects_are_still_broken(tracked):
    """KNOWN_DEFECTS 是自毁清单：一旦缺陷被修好，本测试变红，逼你删条目。

    （这是"不许为了变绿把缺陷塞进例外列表"的机器保证：条目只在缺陷真实存在时才合法。）
    """
    fixed = []
    for tok in KNOWN_DEFECTS:
        ok = False
        for cand in _span_candidates(tok):
            o, _w = _alive(cand, tracked)
            if o and not _is_excluded(cand, rel.EXCLUDE_DIRS, rel.EXCLUDE_FILES):
                ok = True
                break
        if ok:
            fixed.append(tok)
    assert not fixed, (
        "以下 KNOWN_DEFECTS 条目已被修好，请从 KNOWN_DEFECTS 字典中删除（不许常驻）："
        f"{fixed}")


def test_allowlist_entries_still_absent(tracked):
    """ALLOWLIST 条目必须真的不在仓库里——若哪天进了仓库，说明该条目失效，应删除。"""
    now_present = []
    for tok in ALLOWLIST:
        for cand in _span_candidates(tok):
            if _alive(cand, tracked)[0]:
                now_present.append(tok)
                break
    assert not now_present, (
        f"以下 ALLOWLIST 条目现在能在仓库里找到，理由已失效，请删除或改写理由：{now_present}")


def test_every_exception_has_a_reason():
    """每条例外必须有非空的书面理由（防"先塞进去再说"）。"""
    for tok, reason in list(ALLOWLIST.items()) + list(KNOWN_DEFECTS.items()):
        assert reason and len(reason.strip()) >= 10, f"例外 {tok} 缺少书面理由"
