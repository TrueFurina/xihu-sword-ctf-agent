# -*- coding: utf-8 -*-
"""发布闸政策对齐的机器可查护栏（2026-09-19 政策收口）。

钉死三件事，防止后人凭直觉改回"更严的旧策略"，或反过来把安全防线一起改成 WARN：

  1. **明文 flag → WARN**，不进失败计数、不影响退出码
     （政策依据：用户 2026-08-29「flag 明文公开无实质风险，全都不管了，全都公开！除了
      我的 api,token」+ 2026-09-01「永远，不管答案密钥泄露」；且机器验证器的期望值正是
      tagline「machine-verified」的实现基础，脱敏 = 拆卖点）；
  2. **凭据/密钥 → 硬 FAIL 且退出码非 0**（唯一硬红线，SECRET_PATTERNS 只许追加）；
  3. **政策依据与 machine-verified 论据必须以文字留在 release_export.py 内**
     —— 否则后人读到"flag 不算泄漏"会以为我们偷偷放宽了。

另含双向变异（防松弛 / 防过严）与"声明校正"回归：
  · 塞假凭据 → 退出码非 0；删掉 → 恢复 0；
  · 当前真实跟踪树 --scan-only 退出码 0；
  · .gitignore 不再谎称台账"已脱敏"。
"""
import json
import os
import shutil
import subprocess
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_AGENT = os.path.join(_ROOT, "ctf_agent")
sys.path.insert(0, _AGENT)

import scripts.release_export as rel  # noqa: E402

# 每条 SECRET_PATTERNS 规则的合成样本（用于"只许追加、不许削弱"的逐条体检）。
#
# ⚠️ **必须用拼接构造，不可写成整字面量**：本文件自身会被 scripts/release_export.py
# 的 --scan-only 扫描（发布闸对凭据是 fail-closed 硬红线），若在此写下完整的
# credential 字面量，闸门会（正确地）把本测试文件判为泄漏 → 仓库永远过不了闸。
# 同源先例见 tests/test_no_leaked_flag.py 对 RDD 红线的拼接处理。
_SECRET_SAMPLES: dict[str, str] = {
    "sk_key": "sk-" + "A" * 24,
    "sk_tr_key": "sk_tr_" + "B" * 24,
    "github_pat": "ghp_" + "C" * 24,
    "bearer_token": "Bearer " + "D" * 24,
    "aws_access_key_id": "AKIA" + "ABCDEFGHIJKLMNOP",
    "google_api_key": "AIza" + "E" * 35,
    "slack_token": "xoxb-" + "1234567890ab",
    "pem_private_key": "-----BEGIN RSA " + "PRIVATE KEY-----",
}


# ───────────────────────────── ① 明文 flag 只算提示 ─────────────────────────────

def test_plaintext_flag_is_warn_not_fail(tmp_path):
    """明文 flag（机器验证器期望值形态）只进 WARN，不进 FAIL。"""
    (tmp_path / "verify_demo.py").write_text(
        "# 期望值（machine-verified 真值）\n"
        "EXPECTED_FLAG = DASCTF{6b3ed7dc3c1c6615fb97a7020922f7a5}\n",
        encoding="utf-8",
    )
    fails, warns = rel.scan_tree(tmp_path)
    assert fails == [], f"明文 flag 不得判为泄漏，实际 FAIL={fails}"
    assert any("明文 flag" in w for w in warns), f"应打印明文 flag 提示，实际 {warns}"


def test_plaintext_flag_verify_exit_zero(tmp_path):
    """含明文 flag 的树 → verify() 退出码 0（不阻断发布）。"""
    (tmp_path / "verify_specialcurve2.py").write_text(
        "# flag = DASCTF{long_to_bytes(Mx)+long_to_bytes(My)}\n", encoding="utf-8",
    )
    assert rel.verify(tmp_path) == 0


def test_ledger_style_plaintext_flags_pass(tmp_path):
    """台账风格的明文 flag（VNCTF 规范行）→ 一律 WARN，零 FAIL。"""
    (tmp_path / "REAL_SOLVES_LEDGER.md").write_text(
        "- **flag（规范）**：`<VNCTF{93ee7688-f216-42cb-a5c2-191ff4e412ba} "
        "sha256=a9bb88af16508d85215cfd72a3145a8db76d54930fbd5a1834d032e2309606fa>`\n",
        encoding="utf-8",
    )
    fails, warns = rel.scan_tree(tmp_path)
    assert fails == []
    assert warns, "台账明文 flag 应至少产生一条 WARN 提示"


# ───────────────────────────── ② 凭据是硬红线 ─────────────────────────────

def test_secret_causes_fail_and_nonzero_exit(tmp_path):
    """假真凭据（ghp_ + 24 位）→ FAIL 且 verify() 退出码非 0。"""
    (tmp_path / "leaked.txt").write_text(
        "export GITHUB_TOKEN=ghp_" + "C" * 24 + "\n", encoding="utf-8",
    )
    fails, _ = rel.scan_tree(tmp_path)
    assert fails, "凭据必须硬失败"
    assert "凭据/密钥" in fails[0]
    assert rel.verify(tmp_path) == 1, "凭据泄漏必须让自检退出码非 0"


@pytest.mark.parametrize("name,sample", sorted(_SECRET_SAMPLES.items()))
def test_every_secret_pattern_still_fires(tmp_path, name, sample):
    """逐条体检：SECRET_PATTERNS 里每一条正则都必须仍能命中其样本（防被削弱/删空）。"""
    hit = rel.SECRET_RE.search(sample)
    assert hit is not None, f"规则 {name} 已失效，样本未被命中"
    assert hit.lastgroup == name, f"样本 {sample[:12]}… 命中 {hit.lastgroup}，期望 {name}"
    (tmp_path / "leak.env").write_text(sample + "\n", encoding="utf-8")
    fails, _ = rel.scan_tree(tmp_path)
    assert fails, f"规则 {name} 命中后在扫描树里必须产生 FAIL"


def test_secret_pattern_list_is_the_declared_redline():
    """硬红线名单完整性：八类凭据形态一条都不能少。"""
    names = [n for n, _ in rel.SECRET_PATTERNS]
    assert len(names) == len(set(names)), "SECRET_PATTERNS 存在重名规则"
    for required in ("sk_key", "sk_tr_key", "github_pat", "bearer_token",
                     "aws_access_key_id", "google_api_key", "slack_token",
                     "pem_private_key"):
        assert required in names, f"硬红线规则缺失: {required}"
    # GitHub PAT 家族必须覆盖 ghp_/gho_/ghu_/ghs_/ghr_
    gh = dict(rel.SECRET_PATTERNS)["github_pat"]
    for prefix in ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"):
        assert rel.SECRET_RE.search(prefix + "Z" * 24) is not None, f"{prefix} 未被覆盖"


# ───────────────── ③ 政策依据必须留在源码里（防"偷偷放宽"误读） ─────────────────

def test_policy_rationale_documented_in_source():
    src = (rel.__file__, )
    with open(src[0], encoding="utf-8") as fh:
        text = fh.read()
    for needle in ("2026-08-29", "2026-09-01", "永远，不管答案密钥泄露",
                   "全都不管了，全都公开", "machine-verified", "SECRET_PATTERNS",
                   "硬红线", "flag_sha256", "92 题"):
        assert needle in text, f"release_export.py 政策注释缺失关键依据：{needle}"


# ───────────────────────── ④ 脱敏函数：范围如实 + 默认不跑 ─────────────────────────

def test_redact_flags_defaults_off():
    """--redact-flags 默认关闭（政策上明文 flag 非泄漏，脱敏会毁掉 machine-verified 真值）。"""
    assert rel.build_arg_parser().parse_args([]).redact_flags is False
    assert rel.build_arg_parser().parse_args(["--redact-flags"]).redact_flags is True


def test_redact_question_flags_covers_only_top_level_flag(tmp_path):
    """如实覆盖范围：只动路径含 questions 的 JSON 的顶层 flag 键，description/flag_sha256 不动。"""
    qdir = tmp_path / "data" / "questions_real" / "web"
    qdir.mkdir(parents=True)
    q = qdir / "real_web_demo.json"
    sha = "a1a65ec215e740dfead9be11ad54c534cac6848d1fe49d0b398254255942d0d2"
    q.write_text(json.dumps({
        "flag": sha,               # 实测：题库 flag 字段本身就是 sha256 真值载体
        "flag_sha256": sha,
        "description": "真 flag 明文写在 description 里 flag{wwwWow_u_2re_sql_master}",
    }, ensure_ascii=False), encoding="utf-8")
    other = tmp_path / "config" / "settings.json"
    other.parent.mkdir(parents=True)
    other.write_text(json.dumps({"flag": "keep-me"}), encoding="utf-8")

    assert rel.redact_question_flags(tmp_path) == 1
    data = json.loads(q.read_text(encoding="utf-8"))
    assert data["flag"] == "<redacted>"
    assert data["flag_sha256"] == sha, \
        "flag_sha256 绝不能被抹掉（那才是真的丢真值）"
    assert "flag{wwwWow_u_2re_sql_master}" in data["description"], \
        "description 不在覆盖范围（这正是'不等于题库已脱敏'的原因）"
    assert json.loads(other.read_text(encoding="utf-8"))["flag"] == "keep-me", \
        "非 questions 路径的 JSON 不得改动"


# ───────────────────────── ⑤ 双向变异（防松弛 / 防过严） ─────────────────────────

def _git(repo, *args):
    return subprocess.run(["git", *args], cwd=str(repo), capture_output=True, text=True)


@pytest.mark.skipif(shutil.which("git") is None, reason="需要 git")
def test_mutation_both_directions(tmp_path, monkeypatch):
    """方向一：塞假凭据 → 退出码非 0；删掉 → 恢复 0。方向二：明文 flag → 始终 0。"""
    assert _git(tmp_path, "init", "-q").returncode == 0
    monkeypatch.setattr(rel, "repo_root", lambda: tmp_path)

    flag_py = tmp_path / "verify_10732.py"
    flag_py.write_text("EXPECTED = DASCTF{6b3ed7dc3c1c6615fb97a7020922f7a5}\n",
                       encoding="utf-8")
    assert _git(tmp_path, "add", "verify_10732.py").returncode == 0
    # 方向二（防过严）：明文 flag 不阻断
    assert rel.scan_current() == 0

    leak = tmp_path / "leaked.env"
    leak.write_text("token=ghp_" + "C" * 24 + "\n", encoding="utf-8")
    assert _git(tmp_path, "add", "leaked.env").returncode == 0
    # 方向一（防松弛）：假凭据必须硬失败
    assert rel.scan_current() == 1, "塞入假真凭据后闸门必须 FAIL"

    _git(tmp_path, "rm", "--cached", "-q", "leaked.env")
    leak.unlink()
    assert rel.scan_current() == 0, "移除假凭据后闸门应恢复放行"


@pytest.mark.skipif(shutil.which("git") is None, reason="需要 git")
def test_current_tracked_tree_passes_gate():
    """端到端：当前真实跟踪树 --scan-only 退出码必须为 0（明文 flag 不再阻断发布）。"""
    script = os.path.join(_AGENT, "scripts", "release_export.py")
    r = subprocess.run([sys.executable, script, "--scan-only"], cwd=_AGENT,
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=600)
    assert r.returncode == 0, f"扫描闸应放行，实际 {r.returncode}\n{r.stdout[-3000:]}"


# ───────────────────────── ⑥ 声明校正回归（.gitignore） ─────────────────────────

def test_gitignore_ledger_comment_is_factual():
    """台账注释不得再谎称"已脱敏"；须写明它被跟踪且含明文 flag（政策允许）。"""
    text = open(os.path.join(_AGENT, ".gitignore"), encoding="utf-8").read()
    assert "现已脱敏" not in text, ".gitignore 仍含'台账现已脱敏'假声明"
    assert "REAL_SOLVES_LEDGER.md" in text
    assert "处于版本控制中" in text and "含明文 flag" in text
    assert "SECRET_PATTERNS" in text, "应指向 release_export.py 的硬红线规则集"
