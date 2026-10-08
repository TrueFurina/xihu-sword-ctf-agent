# -*- coding: utf-8 -*-
"""provider「谁活着」必须来自机器快照——不得手写（2026-10-08）。

背景
----
同一类故障在本仓第四次复发：把某次真实探测的结论手写进注释/默认值，
几周后余额/权限/限流变了，注释变假话，而跑批默认值照它配 → 整轮打到死源。
本次的处置是把结论从注释搬进 `scripts/_llm_pool_status.py` 的落盘快照；
本文件守住后半件事：**不许再有人手写一句「某源可用」回来**。

两条不变式
──────────
A. **功能性**：`_llm_pool_status` 只认新鲜快照——没有/过期/损坏 → 回答「没人活着」
   （fail-closed），绝不退化成「全部可用」或「按某种猜测给个默认」。
B. **源码级**：生产文件里不得出现手写存活声明。用 AST + tokenize 查两类：
   - A 规则：注释行同时含「provider 名」与「存活断言词」（两者都出现才算，避免把
     「HTTP 200 但业务码非 00000」这类正常叙述误判为存活声明）；
   - B 规则：字符串常量（含 docstring）含存活断言词（这类是全 canopy 对外的证书，
     例如档位描述会直接打印到操作员屏幕上，写错比不写更糟）。

诚实边界
--------
- 源码扫描是**词表匹配**，不是语义理解：换个没进词表的说法（「稳定 beberapa 周」）
  它抓不到。它守的是「历史上反复犯的那一类措辞」，不是所有虚假陈述。
- 因此配 `TestScannerSelfCheck`：**用合成源码证明扫描器会响**。B 类护栏在真实仓库
  上恒为「当前 0 命中」，不配合成自检的话，把词表清空也没人会发现。

❗ 测试自身不是发射道（project memory ㉗）：本文件全程离线，不碰网络、不落生产目录
（所有读写都走 monkeypatch 后的临时目录）。
"""
import ast
import importlib
import io
import re
import sys
import tokenize
from datetime import datetime
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def _status():
    return importlib.import_module("scripts._llm_pool_status")


@pytest.fixture
def probe_dir(tmp_path, monkeypatch):
    """把快照目录指到本测试专属临时目录（不碰生产 logs/）。"""
    d = tmp_path / "probe"
    d.mkdir()
    monkeypatch.setenv("CTF_AGENT_PROBE_DIR", str(d))
    return d


# ───────────────────────── A. 功能性 ─────────────────────────


class TestSnapshotTruth:
    def test_roundtrip_only_ok_counts(self, probe_dir):
        st = _status()
        st.write_record([
            {"provider": "glm", "status": "OK", "detail": "glm-4.7 200"},
            {"provider": "baidu", "status": "HTTP403", "detail": "permission"},
            {"provider": "deepseek", "status": "HTTP402", "detail": "balance"},
        ], ts=datetime(2026, 10, 8, 3, 0, 0))
        rec = st.latest_record(now=datetime(2026, 10, 8, 4, 0, 0))
        assert rec is not None, "刚写的快照必须能被读到"
        assert st.live_providers(now=datetime(2026, 10, 8, 4, 0, 0)) == {"glm"}
        assert st.is_live("glm", now=datetime(2026, 10, 8, 4, 0, 0)) is True
        assert st.is_live("baidu", now=datetime(2026, 10, 8, 4, 0, 0)) is False

    def test_latest_snapshot_wins(self, probe_dir):
        st = _status()
        st.write_record([{"provider": "old", "status": "OK"}],
                        ts=datetime(2026, 10, 8, 1, 0, 0))
        st.write_record([{"provider": "new", "status": "OK"}],
                        ts=datetime(2026, 10, 8, 2, 0, 0))
        live = st.live_providers(now=datetime(2026, 10, 8, 3, 0, 0))
        assert live == {"new"}, f"应只认最新快照，实际 {live}"

    def test_expired_snapshot_is_not_truth(self, probe_dir):
        """过期快照＝没有快照（fail-closed）。这条例外最危险：放宽容忍窗口就等于
        把一个月的陈旧结论当今天的用。"""
        st = _status()
        st.write_record([{"provider": "glm", "status": "OK"}],
                        ts=datetime(2026, 10, 1, 0, 0, 0))
        now = datetime(2026, 10, 8, 0, 0, 0)
        assert st.latest_record(now=now) is None
        assert st.live_providers(now=now) == set()
        assert st.is_live("glm", now=now) is False

    def test_missing_directory_yields_unknown_not_all_live(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CTF_AGENT_PROBE_DIR", str(tmp_path / "nope"))
        st = _status()
        assert st.list_records() == []
        assert st.live_providers() == set()
        for p in ("glm", "baidu", "qwen"):
            assert st.is_live(p) is False, f"无快照时 {p} 必须回答不可用（未知≠可用）"

    def test_unknown_and_blank_provider_are_false(self, probe_dir):
        st = _status()
        st.write_record([{"provider": "glm", "status": "OK"}],
                        ts=datetime(2026, 10, 8, 3, 0, 0))
        now = datetime(2026, 10, 8, 3, 30, 0)
        assert st.is_live("never_probed", now=now) is False
        assert st.is_live("", now=now) is False

    def test_corrupt_snapshot_does_not_break_and_is_not_truth(self, probe_dir):
        st = _status()
        (probe_dir / "20261008T030000.json").write_text("{ 不是 json", encoding="utf-8")
        assert st.latest_record(now=datetime(2026, 10, 8, 4, 0, 0)) is None
        # 损坏的旧快照不应连带废掉更新写的那张
        st.write_record([{"provider": "glm", "status": "OK"}],
                        ts=datetime(2026, 10, 8, 3, 30, 0))
        assert st.live_providers(now=datetime(2026, 10, 8, 4, 0, 0)) == {"glm"}

    def test_stale_boundary_is_inclusive_up_to_window(self, probe_dir):
        st = _status()
        st.write_record([{"provider": "glm", "status": "OK"}],
                        ts=datetime(2026, 10, 7, 0, 0, 0))
        now = datetime(2026, 10, 8, 0, 0, 0)  # 恰好 24h
        assert st.is_live("glm", max_age_hours=24, now=now) is True
        assert st.is_live("glm", max_age_hours=23, now=now) is False

    def test_describe_distinguishes_unknown_from_all_dead(self, probe_dir):
        """两者处置相同（都不可用）但归因不同：前者先去探测，后者先去充值。"""
        st = _status()
        msg = st.describe(now=datetime(2026, 10, 8, 4, 0, 0))
        assert "未知" in msg and "_probe_providers.py" in msg
        st.write_record([{"provider": "baidu", "status": "HTTP403"}],
                        ts=datetime(2026, 10, 8, 3, 0, 0))
        msg2 = st.describe(now=datetime(2026, 10, 8, 4, 0, 0))
        assert "未知" not in msg2 and "HTTP403" in msg2

    def test_cli_require_reflects_snapshot(self, probe_dir):
        st = _status()
        st.write_record([{"provider": "glm", "status": "OK"}],
                        ts=datetime(2026, 10, 8, 3, 0, 0))
        assert st.main(["--require", "glm", "--record-dir", str(probe_dir)]) == 0
        assert st.main(["--require", "qwen", "--record-dir", str(probe_dir)]) == 1


# ───────────────────── B. 源码级：不许手写存活声明 ─────────────────────

# 生产文件清单：**历史上反复手写此类声明的那几处**（默认 provider、逃生开关、
# 降级顺序、竞速档位、赛前门禁）。不是全仓扫描——全仓会把「HTTP 200 但业务码非
# 00000」「实探命令提示」等正常叙述卷进来，天天假红的护栏最终会被人整段注释掉。
TARGET_FILES = [
    "config.py",
    "llm/client.py",
    "llm/failover.py",
    "scripts/_race_start.py",
    "scripts/_preflight_env.py",
    "scripts/_probe_providers.py",
    "scripts/_llm_health_probe.py",
    "scripts/_llm_pool_status.py",
]

# 存活断言词。刻意不含「70200 OK」「HTTP 200」——那些是全类通用状态码叙述
# （如「HTTP 200 但业务码非 00000」），混进来会让扫描器天天假红进而被注释掉。
LIVENESS_PHRASES = [
    "实测存活",
    "实测可用",
    "实测通过",
    "已知可用",
    "可用主源",
    "已充值",
    "充值后",
    "稳定可用",
    # 刻意不含「存活源」：那词在本仓有两处合法用法（`llm/client.py` 熔断日志里的
    # 「剩余存活源」、`_net_check.py` 的运维提示），指的是**运行期动态发现的剩余可用
    # 路由**，不是对某个具体源的手写承诺。词表一旦误伤合法叙述，护栏就会天天假红，
    # 结局是被整段注释掉——比少守一个词更糟。手写的静态声明几乎总以「实测存活 /
    # 已知可用」等形态出现，已被上表覆盖。
]

PROVIDER_TOKENS = [
    "baidu", "qwen", "deepseek", "glm", "tokenhub", "mimo", "moonshot",
    "kimi", "ark", "xfyun", "tencent", "siliconflow", "minimax", "stepfun",
    "baichuan", "step",
    "千帆", "百炼", "智谱", "讯飞", "豆包", "混元", "硅基",
]

_PROVIDER_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:" + "|".join(PROVIDER_TOKENS) + r")(?![A-Za-z0-9_])",
    re.IGNORECASE,
)


def _comment_lines(path: Path):
    """取出文件内所有注释行文本（tokenize 的 COMMENT token）。"""
    src = path.read_text(encoding="utf-8", errors="ignore")
    out = []
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type == tokenize.COMMENT:
            out.append(tok.string)
    return out


def _string_constants(path: Path):
    """取出所有字符串常量（含 docstring）。"""
    tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
    return [n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def scan_repo_violations(root: Path = _ROOT, files=None):
    """扫描目录内的违规声明，返回 [(相对路径, 类型, 命中文案)]。

    `files` 可覆盖目标清单——**这条接口是给合成自检用的**：自检必须穿透唯一入口，
    否则「在合成数据里重抄一份同样逻辑」的自检会在真护栏被删掉后照样绿（见
    TestScannerSelfCheck 的说明，这是模仿型自检不算护栏的又一实例）。
    """
    hits = []
    for rel in (TARGET_FILES if files is None else files):
        p = root / rel
        if not p.is_file():
            continue
        for line in _comment_lines(p):
            if any(ph in line for ph in LIVENESS_PHRASES) and _PROVIDER_RE.search(line):
                hits.append((rel, "comment", line.strip()[:120]))
        for s in _string_constants(p):
            hit = next((ph for ph in LIVENESS_PHRASES if ph in s), None)
            if hit:
                hits.append((rel, "string", f"[{hit}] {s.strip()[:90]}"))
    return hits


class TestNoHandwrittenLiveness:
    """生产文件里不得再出现手写的 provider 存活声明（第四次复发同一故障的护栏）。"""

    def test_repo_has_no_handwritten_liveness_claims(self):
        hits = scan_repo_violations()
        assert hits == [], (
            "以下位置手写了对某个 provider 的存活声明。可用性随余额/权限/限流漂移，"
            "注释写完即开始腐烂；改为引用 `scripts/_llm_pool_status.py` 的新鲜快照：\n"
            + "\n".join(f"  {rel} [{kind}] {text}" for rel, kind, text in hits)
        )

    def test_guard_covers_the_files_it_should(self):
        """目标文件必须真实存在——路径写错会让护栏静默失效（变空列表恒过）。"""
        missing = [rel for rel in TARGET_FILES if not (_ROOT / rel).is_file()]
        assert missing == [], f"护栏的目标文件不存在，扫描已失效: {missing}"


class TestScannerSelfCheck:
    """合成源码自检：证明扫描器不是空壳。

    B 类护栏在真实仓库上恒为「0 命中」——这种护栏的真实分枝永远跑不到，
    把词表清空或把正则写反都照样绿。必须用合成数据把两条规则都点亮一次。
    """

    def test_detects_comment_claim(self, tmp_path):
        bad = tmp_path / "evil.py"
        bad.write_text(
            "# -*- coding: utf-8 -*-\n"
            "X = 1  # 改用实测存活源（glm 主 + ark 备用）\n",
            encoding="utf-8")
        hits = []
        for line in _comment_lines(bad):
            if any(ph in line for ph in LIVENESS_PHRASES) and _PROVIDER_RE.search(line):
                hits.append(line)
        assert hits, "合成的手写存活声明未被扫描器发现——护栏为空壳"

    def test_detects_string_claim(self, tmp_path):
        bad = tmp_path / "evil2.py"
        bad.write_text(
            'LABEL = "ultra(11路实测存活: 千帆+智谱+讯飞)"\n',
            encoding="utf-8")
        strs = _string_constants(bad)
        assert any(ph in s for s in strs for ph in LIVENESS_PHRASES), \
            "合成的字符串常量存活声明未被扫描器发现——护栏为空壳"

    def test_ignores_neutral_narrative(self, tmp_path):
        """反向自检：「HTTP 200 但业务码非 00000」这类状态码叙述不该被判违规，
        否则护栏天天假红，最终会被人整段注释掉。"""
        good = tmp_path / "ok.py"
        good.write_text(
            "# ① 先打原始请求校验业务码：HTTP 200 但业务码非 00000 仍属失败\n"
            "MSG = 'quota exceeded 402 / forbidden 403 / rate limited 429'\n",
            encoding="utf-8")
        hits = []
        for line in _comment_lines(good):
            if any(ph in line for ph in LIVENESS_PHRASES) and _PROVIDER_RE.search(line):
                hits.append(line)
        strs = _string_constants(good)
        assert not hits and not any(ph in s for s in strs for ph in LIVENESS_PHRASES)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
