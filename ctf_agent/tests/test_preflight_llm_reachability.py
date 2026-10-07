"""赛前环境门禁必须真正验证 LLM 主链可达性（2026-10-08）。

背景
────
`scripts/_preflight_env.py` 自称「全部 PASS 才可开赛」，但原有 ①②③④ 四项
（python 输出 / 拉题链路 / 大文件 / 网关配置）**没有一项验证 LLM 真能发通请求**。

而 LLM provider 恰是全链路最常失效的一环——历史上曾一度出现 qwen 欠费、
deepseek 402、baidu 403、moonshot 429 同时不可用的局面。后果是：

    门禁全绿 → 判定「可开赛」→ 一开赛 LLM 全瘫。

这比某一项报红危险得多：**红是提示，绿是承诺**。一个名字里写着「环境 100%
可用」的门禁，漏验最会失效的那一环，等于把承诺给错了对象。

补上第 ⑤ 项后，不变式是：**没验过 LLM 就绝不输出「可开赛」**。

为什么默认不联网
────────────────
provider 可用性随余额/欠费/平台策略随时变化，门禁不该因为欠费而永久变红；
但同样不该悄悄跳过让人误以为验过了。所以默认值是 `probe=None` —— **不联网**，
只打印「未探测」并明确标注不计入 PASS；真要验就显式 `--probe-llm`。

🔴 本测试的发射道约束（见 project memory ㉗）
──────────────────────────────────────────
所有用例**一律注入 mock probe**，任何路径都不得调用真正的 `default_llm_probe`。
否则「守卫被写坏」时，测试自己就会发出真实请求、烧掉预算。
原则：**测试失败必须只是断言失败，不能是账单。**

其中 `test_default_does_not_touch_network` 会把 `default_llm_probe` 打桩成
抛 AssertionError —— 一旦有人让默认路径去联网，该用例立刻红。

锁死的不变式
────────────
① 未探测 LLM 时，即使前四项全绿，也不得输出「可开赛」（必须 fail-closed）。
② `probe` 的四种分支：成功→True / 失败→False / 抛异常→False / 解析不到
   provider→False。探测器自身炸了必须结论化为失败，不能被吞成成功。
③ 默认路径（`main([])`）不得调用真实探测器。
④ `resolve_effective_provider()` 与单一真相源 `_facts.effective_provider_value()`
   同源 —— 本文件不许再写第二套 provider 解析。

变异验证
────────
- M1 `check_llm_reachability` 吞掉异常（except → return True）
  → 1 failed（MSC-2 探测器异常）
- M2 `verdict()` 放宽为 `passed >= total` 不看 probed
  → 5 failed，**5 个全部来自合成自检**——真实环境的用例一个都没抓住它。
    （CI 上前四项几乎不可能全绿，`passed >= total` 那条分支根本走不到。）
- M3 `verdict()` 恒返回「✅ 可开赛」
  → 34 failed，同样由合成自检抓住
- M4 `check_llm_reachability(None)` 也 append 进 results（未探测计入 PASS）
  → 1 failed（test_unprobed_llm_is_not_counted_as_pass）

⚠️ M2/M3 说明：真实环境下「前四项全绿」这个分支在 CI 上几乎跑不到，所以
缺少 `TestVerdictSynthetic` 这类合成自检时，**weakening mutation 必然存活**
（详见 project memory ⑳ M2 教训）。
"""

from __future__ import annotations

import io
import contextlib
import importlib
import sys
import unittest
import unittest.mock as mock

pfe = importlib.import_module("scripts._preflight_env")

try:
    _facts = importlib.import_module("scripts._facts")
except Exception:  # noqa: BLE001 - 无 _facts 时跳过同源性用例
    _facts = None


def probe_ok(_provider):
    return True, "响应正常"


def probe_fail(_provider):
    return False, "403 account_overdue"


def probe_boom(_provider):
    raise RuntimeError("探针自爆")


class TestUnprobedLlmIsNotCountedAsPass(unittest.TestCase):
    """① 没验过 LLM 就不能宣称可开赛。"""

    def test_verdict_never_says_ok_when_not_probed(self):
        # 即使 4/4 全绿，未探测也必须降级为 ⚠️ 而非 ✅
        text = pfe.verdict(passed=4, total=5, probed=False)
        self.assertNotIn("可开赛", text.split("——")[0] + text, )
        self.assertIn("未验证 LLM", text)
        # 全绿且已探测时才允许 ✅
        self.assertIn("可开赛", pfe.verdict(passed=5, total=5, probed=True))

    def test_unprobed_llm_is_not_counted_as_pass(self):
        """M4 靶：未探测的 ⑤ 不得进入 results（不得被算成 PASS）。"""
        with mock.patch.object(pfe, "check_python_output", return_value=True), \
             mock.patch.object(pfe, "check_link", return_value=True), \
             mock.patch.object(pfe, "check_bigfile", return_value=True), \
             mock.patch.object(pfe, "check_config", return_value=True), \
             mock.patch.object(pfe, "check_llm_reachability", return_value=True) as chk:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = pfe.main([])
            out = buf.getvalue()
        # 未给 --probe-llm，不得把返回值塞进 results → passed 只能是 4，不能是 5
        self.assertIn("4/5", out, "⑤ 未探测却被计入 PASS（NO_PROBE 被当成通过）")
        self.assertNotIn("5/5", out)
        self.assertEqual(1, rc, "未验 LLM 却返回了可开赛退出码")
        chk.assert_called_once()  # 仍应调用一次以打印「未探测」提示


class TestProbeBranches(unittest.TestCase):
    """② probe 的四种分支必须结论化为明确的成功/失败。"""

    def _run(self, provider, probe):
        with mock.patch.object(pfe, "resolve_effective_provider", return_value=provider):
            return pfe.check_llm_reachability(probe=probe)

    def test_success(self):
        self.assertTrue(self._run("glm", probe_ok))

    def test_failure(self):
        self.assertFalse(self._run("glm", probe_fail))

    def test_probe_exception_is_failure_not_success(self):
        """探测器炸了必须是失败——不能被兜底吞成成功（M1 靶）。"""
        self.assertFalse(self._run("glm", probe_boom))

    def test_no_provider_is_failure(self):
        self.assertFalse(self._run("", probe_ok))

    def test_none_probe_reports_unprobed(self):
        """probe=None 时返回 True（不阻断），但输出必须如实说「未探测」。"""
        with mock.patch.object(pfe, "resolve_effective_provider", return_value="glm"):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                ok = pfe.check_llm_reachability(probe=None)
            out = buf.getvalue()
        self.assertTrue(ok, "未探测不应阻断门禁")
        self.assertIn("未探测", out)
        self.assertNotIn("✅", out, "未探测却打印了 PASS 标记")


class TestDefaultIsOffline(unittest.TestCase):
    """③ 默认路径不得联网。"""

    def test_default_does_not_touch_network(self):
        sentinel = AssertionError("默认路径不得调用真实探测器（会真发请求、烧预算）")
        with mock.patch.object(pfe, "check_python_output", return_value=True), \
             mock.patch.object(pfe, "check_link", return_value=True), \
             mock.patch.object(pfe, "check_bigfile", return_value=True), \
             mock.patch.object(pfe, "check_config", return_value=True), \
             mock.patch.object(pfe, "default_llm_probe", side_effect=sentinel), \
             mock.patch.object(pfe, "check_llm_reachability", wraps=pfe.check_llm_reachability):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                pfe.main([])  # 不抛异常即证明未触碰真实探测器

    def test_probe_flag_selects_real_detector(self):
        """给了 --probe-llm 才允许用真实探测器（此处仍注入 mock 观测调用）。"""
        captured = {}

        def fake(provider, probe=None):  # 顶替 check_llm_reachability，须返回 bool
            captured["provider"] = provider
            return True

        with mock.patch.object(pfe, "check_python_output", return_value=True), \
             mock.patch.object(pfe, "check_link", return_value=True), \
             mock.patch.object(pfe, "check_bigfile", return_value=True), \
             mock.patch.object(pfe, "check_config", return_value=True), \
             mock.patch.object(pfe, "check_llm_reachability", side_effect=fake) as chk:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = pfe.main(["--probe-llm"])
        chk.assert_called_once()
        self.assertEqual(0, rc, "全部通过时应返回可开赛退出码")
        self.assertIn("5/5", buf.getvalue())


@unittest.skipIf(_facts is None, "scripts._facts 不可导入")
class TestSingleSourceOfTruth(unittest.TestCase):
    """④ provider 解析不许有第二套实现。"""

    def test_resolve_delegates_to_facts(self):
        self.assertEqual(pfe.resolve_effective_provider(),
                         _facts.effective_provider_value(),
                         "_preflight_env 未复用单一真相源，形成了第二套 provider 解析")


class TestVerdictSynthetic(unittest.TestCase):
    """合成自检：`verdict()` 在真实环境下很难跑到的分支，这里全部覆盖。

    没有这一组用例，M2/M3 这类「把守卫放宽」的变异体会完全存活——因为 CI 上
    前四项几乎不可能全绿，`passed >= total` 那条分支根本走不到。
    """

    def test_matrix(self):
        table = {
            # (passed, total, probed) -> 期望关键词
            (5, 5, True): "可开赛",
            (4, 5, False): "未验证 LLM",
            (3, 5, True): "修复后重跑",
            (3, 5, False): "修复后重跑",
            (0, 5, False): "修复后重跑",
            (4, 4, False): "未验证 LLM",   # total 自动跟随且未探测
            (4, 4, True): "可开赛",
        }
        for args, expect in table.items():
            with self.subTest(args=args):
                self.assertIn(expect, pfe.verdict(*args))

    def test_never_ok_when_unprobed(self):
        """最强的那条不变式：probed=False 时无论 passed 多大都不许「可开赛」。"""
        for total in (1, 3, 5, 9):
            for passed in range(0, total + 1):
                with self.subTest(passed=passed, total=total):
                    self.assertNotIn("可开赛", pfe.verdict(passed, total, probed=False))

    def test_partial_failure_with_probe_is_repair(self):
        """已探测但有任一失败 → 修复后重跑，不得含糊。"""
        for passed in range(0, 5):
            with self.subTest(passed=passed):
                self.assertIn("修复后重跑", pfe.verdict(passed, 5, probed=True))


if __name__ == "__main__":
    unittest.main()
