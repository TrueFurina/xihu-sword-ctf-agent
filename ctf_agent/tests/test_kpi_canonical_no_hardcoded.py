r"""KPI 唯一真值源的**输出自洽**护栏（2026-10-08）。

为什么需要这个测试
──────────────────
`scripts/_kpi_canonical.py` 是项目「对外数字只有一个来源」的那一个来源。
它自己 docstring 写着「禁止手工誊抄数字（誊抄即漂移）」，但 2026-10-08 审计发现
它**违反了给自己立的规矩**，而且是在最要命的位置——**机器输出**里：

  D1  `render_md()` 的「口径铁律」行硬编码「分母是 92」，而 `real_corpus` 机器计数
      早已经是 93（2026-10-03 补齐 10733 后 92→93）。这段话的措辞是
      「凡说能力 X% 必须显式声明分母是 ___」，是所有下游文档被要求照搬的规则；
      真值源在这里说错，下游会连错数字一起继承 —— 比 README 漂移严重得多。
  D2  held-out 摘要行直书「LLM 自主推理 1/2」，而作废说明只写在下方长段落里。
      该数字已被 2026-10-01 两次独立实测推翻（dnui_keyboard 实为 presolve），
      但只读摘要、或复制这一行的人，拿到的正是被推翻的数字。

两者共同点：**陈述一旦离开关联上下文，就自动退化成虚假声明**。
这不是能力问题，是呈现问题 —— 数字都对，摆错了位置就变成撒谎。

锁住的两条不变式
────────────────
  ① 输出里提到的「真题全集分母」必须等于 `real_corpus` 机器值（自洽）。
  ② 摘要里引用历史 held-out 数字时，同一行必须带作废标记（不可断章取义）。

刻意的设计选择
──────────────
- **不锁具体数字**（不写死 92 / 93 / 2）：它们会随数据集增删漂移。这里只锁
  「两个位置说的必须是同一个数」，而且这个数取自 `canonical_kpi()` 本身。
- 检测逻辑抽成**纯函数**，配**合成文本自检**。理由：真数据当前是自洽的，
  所以「检测函数写坏（例如恒返回空）」这类变异体在真数据上**必然存活**。
  校验器本身如果不可校验，整套护栏就是橡皮图章 —— 这与
  `test_corpus_truth_integrity.py` 里 M2 的教训完全一致。

变异验证（已做，结果如实记录）
────────────────────────────
  M1  render_md 分母回退硬编码 92 → **1 failed**（`…denominator_matches_machine_truth`）
  M2  摘要行删除作废标记        → **1 failed**（`…summary_carries_deprecation_marker`）
  M3  检测函数恒返回空（削弱校验）→ **3 failed**，且**全部由合成自检用例抓住** ——
      无合成自检则 M3 完全存活，即这套护栏对自身写坏毫无抵抗力。
"""

from __future__ import annotations

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts import _kpi_canonical as kc  # noqa: E402

# 「real_corpus = N」声明位（render_md 摘要里的权威行）
_REAL_CORPUS_DECL_RE = re.compile(r"real_corpus\s*=\s*(\d+)")
# 「分母是 N」——口径铁律里向所有下游传达的规则；历史上这里硬编码过 92
_DENOMINATOR_RE = re.compile(r"分母是\s*(\d+)")
# held-out 摘要行（以「- **held-out 实测」开头）
_SUMMARY_LINE_RE = re.compile(r"^-\s*\*\*held-out 实测")
# 摘要里被引用的历史 LLM 自主推理数
_LLM_RATIO_RE = re.compile(r"LLM 自主推理\s*(\d+)\s*/\s*(\d+)")
# statement 明确宣告「当前可验证值为 0」——只有此时才要求摘要带作废标记
_DECLARED_ZERO_RE = re.compile(r"当前可验证的大模型自主解出数为\s*0")

_CACHE: dict = {}


def canonical_md() -> str:
    """跑一次真值源并缓存（canonical_kpi 要递归题库，勿每用例重跑）。"""
    if "md" not in _CACHE:
        k = kc.canonical_kpi()
        _CACHE["k"] = k
        _CACHE["md"] = kc.render_md(k)
    return _CACHE["md"]


def canonical_kpi_dict() -> dict:
    canonical_md()
    return _CACHE["k"]


# ── 纯函数：可脱离真数据用合成文本自检 ─────────────────────────────────────

def stale_denominators(md: str, real_corpus: int) -> list:
    """挑出与机器值不一致的「分母是 N」陈述。返回 [(声称值, 机器值), ...]。"""
    return [(int(m.group(1)), real_corpus)
            for m in _DENOMINATOR_RE.finditer(md)
            if int(m.group(1)) != real_corpus]


def summary_lines_missing_marker(md: str, require: bool) -> list:
    """挑出「引用了历史 LLM 数却没同行标作废」的摘要行。require=False 时不要求。"""
    if not require:
        return []
    out = []
    for line in md.splitlines():
        if _SUMMARY_LINE_RE.match(line) and _LLM_RATIO_RE.search(line) \
                and "作废" not in line:
            out.append(line.strip())
    return out


class TestCanonicalSelfConsistency(unittest.TestCase):
    """输出文本必须与机器真值自洽，且不得脱离作废上下文。"""

    def test_render_md_denominator_matches_machine_truth(self):
        """口径铁律里宣示的分母 == real_corpus 机器值（历史硬编码过 92）。"""
        md = canonical_md()
        real_corpus = int(canonical_kpi_dict()["real_corpus"])
        self.assertTrue(real_corpus > 0, "real_corpus 非正，真值源在本环境不可得")
        poke = _REAL_CORPUS_DECL_RE.findall(md)
        self.assertTrue(poke, "输出里找不到 `real_corpus = N` 声明行，锚点缺失")
        stale = stale_denominators(md, real_corpus)
        self.assertEqual([], stale,
                         "口径铁律宣示的分母与机器 real_corpus 不一致：%r" % (stale,))

    def test_render_md_summary_carries_deprecation_marker(self):
        """statement 宣告当前 LLM 自主解出为 0 时，摘要引用的历史数必须同行标作废。"""
        md = canonical_md()
        statement = canonical_kpi_dict().get("statement") or ""
        require = bool(_DECLARED_ZERO_RE.search(statement))
        bad = summary_lines_missing_marker(md, require)
        self.assertEqual([], bad,
                         "摘要引用历史 LLM 自主推理数却未在同一行标作废，"
                         "脱离上下文即构成虚假声明：%r" % (bad,))

    def test_canonical_json_regenerated_is_consistent(self):
        """落盘产物 kpi_canonical.json 的数值字段须与本次计算一致（防陈旧产物被引用）。

        json 本身未入库，但 run/文档可能读它；陈旧 json 与现状不一致则判为漂移。
        """
        k = canonical_kpi_dict()
        path = kc.OUT
        if not path.is_file():
            self.skipTest("尚未生成 %s（跑过一次即出现）" % path.name)
        import json
        data = json.loads(path.read_text(encoding="utf-8"))
        for key in ("real_corpus", "offline_verified", "skills"):
            if key in data:
                self.assertEqual(k[key], data[key],
                                 "%s：落盘产物(%r) ≠ 当前机器值(%r)" % (key, data[key], k[key]))


class TestDetectorSelfCheck(unittest.TestCase):
    """合成自检：真数据当前自洽 ⇒ 『检测器写坏』在真数据上必然存活，必须靠合成文本兜。"""

    def test_stale_denominator_is_detected(self):
        """合成「分母是 92」而机器值 93 → 必须被抓。"""
        md = ("- **real_corpus = 93**（真题全集分母）\n"
              "> 口径铁律：凡说「能力 X%」必须显式声明分母是 92 还是 heldout 子集。\n")
        hits = stale_denominators(md, 93)
        self.assertEqual([(92, 93)], hits)

    def test_summary_without_marker_is_detected(self):
        """合成摘要引用历史数却无作废标记 → 必须被抓。"""
        md = "- **held-out 实测（r.json）**：池内 2/2 / LLM 自主推理 1/2；tokens=1\n"
        hits = summary_lines_missing_marker(md, require=True)
        self.assertEqual(1, len(hits))

    def test_summary_with_marker_passes(self):
        """同一行带作废标记 → 放行（防恒定误报把门禁逼关）。"""
        md = ("- **held-out 实测（r.json）**：池内 2/2 / "
              "报告记为 LLM 自主推理 1/2（⚠️ 已作废：当前可验证的 LLM 自主解出数 = 0）\n")
        self.assertEqual([], summary_lines_missing_marker(md, require=True))

    def test_require_flag_off_never_blocks(self):
        """statement 未宣告 0 时放宽要求 → 不得误报。"""
        md = "- **held-out 实测（r.json）**：池内 2/2 / LLM 自主推理 1/2；tokens=1\n"
        self.assertEqual([], summary_lines_missing_marker(md, require=False))

    def test_detector_not_trivially_empty(self):
        """反向自检：检测器确有检出能力（M3 的杀法）。"""
        self.assertTrue(stale_denominators("分母是 92", 93))
        self.assertTrue(summary_lines_missing_marker(
            "- **held-out 实测**：LLM 自主推理 1/2", require=True))


if __name__ == "__main__":
    unittest.main()
