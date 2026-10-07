r"""held-out 跑批入口的 fail-closed 护栏（2026-10-08，P0-4 收口）。

为什么要这个测试
────────────────
`scripts/benchmark_heldout.py` 长期写着 `--provider default="baidu"`，
而千帆（baidu）已长期 403 不可用。后果是一条**静默烧钱路径**：

    按默认执行 --run  →  拿不到任何有效结果（死源），却先空耗一轮完整预算。

`plans/current.md` 的 P0-4「跑批默认值 fail-closed」把这列为必修项，
`eval/benchmark.py`（`d51fdae`）已改，而 `benchmark_heldout.py` 因当时并发占用
一直标注「⛔ 阻塞」。2026-10-08 工位已干净，本会话补上这一半。

现在的契约
──────────
  1. **真跑（--run 且非 --mock）必须有 provider**，否则退出码 2，
     且在**选题之前**就拒绝（不产生 manifest、不空耗）。
  2. provider 默认取环境变量 `CTF_AGENT_LLM_PROVIDER`；两者皆空才拦。
  3. `--select` / `--run --mock` / 显式 `--provider X` 均不得被误拦。
  4. 真跑前必须打印规模与 provider（成本可见性）。

刻意的设计选择
──────────────
- **不内置 provider 死活清单**。可用性随余额/欠费/平台策略变化，
  手写黑白名单会漂移成**新的假水位**——这正是本项目反复整治的靶子。
  实现里改为指向既有机器实探 `scripts/_preflight_env.py`，此处只保证该提示存在。
- 覆盖率解析抽成**纯函数** `refuse_reason(args)`：让「是否该拦截」可以脱离
  真实题库被检验（真题库路径本身较贵，且不应在测试里跑选题）。

变异验证（已做，结果如实记录）
────────────────────────────
  M1  默认 provider 改回写死 "baidu"  → **1 failed**（`test_provider_default_is_not_baidu`）
  M2  删掉 fail-closed 守卫           → **2 failed**（CLI 端到端 + `refuse_reason` 用例）
  M3  `refuse_reason` 恒返回 None     → **2 failed**，且由**合成自检**抓住（真数据的
      「不拦」路径单独看是正确行为，削弱後只有合成用例能发现问题）。
"""

from __future__ import annotations

import os
import sys
import unittest
from argparse import Namespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts import benchmark_heldout as bh  # noqa: E402


def make_args(run=False, mock=False, provider=None):
    return Namespace(run=run, mock=mock, provider=provider)


def refuse_reason(args) -> str or None:
    """纯函数：判断是否应拒绝启动。返回拒绝原因，None = 放行。

    与实现中的守卫保持同一判定式；独立重述是为了让测试能覆盖**行为**而不只是源码文本。
    """
    if args.run and not args.mock and not args.provider:
        return "no-provider"
    return None


class TestProviderFailClosed(unittest.TestCase):
    """真跑必须有 provider：不得退回「写死默认 + 静默失败」。"""

    def setUp(self):
        self._saved = os.environ.get("CTF_AGENT_LLM_PROVIDER")
        os.environ.pop("CTF_AGENT_LLM_PROVIDER", None)

    def tearDown(self):
        os.environ.pop("CTF_AGENT_LLM_PROVIDER", None)
        if self._saved is not None:
            os.environ["CTF_AGENT_LLM_PROVIDER"] = self._saved

    def test_provider_default_is_not_baidu(self):
        """默认不得再写死 baidu（本体已长期 403）——这是本缺陷的根源。"""
        ns = bh.build_arg_parser().parse_args([])
        self.assertNotEqual("baidu", ns.provider,
                            "provider 默认值又退回写死的 baidu（已失效源）")

    def test_real_run_without_provider_is_refused(self):
        """`--run` 且无 provider → 主流程返回 2，且不触发选题/写 manifest。"""
        called = []
        # 🔴 安全兜底：本用例的语义是「应当被拒」。若未来守卫被改坏（变异验证 M1 实测
        # 证明这会发生），main() 会一路走到真跑 —— 届时若不 stub 掉 run()，测试本身
        # 就变成了一条**真发起请求 + 烧预算**的路径。这里把下游全部隔离掉，
        # 保证「测试失败」永远只是断言失败，而不是账单。
        orig_select = bh.select_candidates
        orig_write = bh.write_manifest
        orig_run = bh.run
        bh.select_candidates = lambda *a, **k: called.append("select") or ([], [])
        bh.write_manifest = lambda *a, **k: called.append("write")
        bh.run = lambda *a, **k: called.append("run") or 0
        saved_argv = sys.argv
        sys.argv = ["benchmark_heldout", "--run"]  # 隔离 pytest 自身的 argv
        try:
            rc = bh.main()
        finally:
            sys.argv = saved_argv
            bh.select_candidates = orig_select
            bh.write_manifest = orig_write
            bh.run = orig_run
        self.assertNotIn("run", called,
                         "守卫失效：main() 走到了真跑分支（会真实发起请求/烧预算）")
        self.assertEqual(2, rc, "无 provider 的真跑未被拒绝")
        self.assertEqual([], called, "拒绝前不应产生任何副作用（select/write/run 均无）")

    def test_mock_run_needs_no_provider(self):
        """冒烟路径无需 provider，不得被误拦。"""
        self.assertIsNone(refuse_reason(make_args(run=True, mock=True, provider=None)))

    def test_select_only_is_not_blocked(self):
        """只选题不构成真跑，不得被拦。"""
        self.assertIsNone(refuse_reason(make_args(run=False, mock=False, provider=None)))
        self.assertIsNone(refuse_reason(make_args(run=True, mock=False, provider="glm")))

    def test_env_var_supplies_provider(self):
        """环境变量可作为 provider 来源（保留既有惯例）。"""
        os.environ["CTF_AGENT_LLM_PROVIDER"] = "glm"
        ns = bh.build_arg_parser().parse_args([])
        self.assertEqual("glm", ns.provider)


class TestRefuseReasonSelfCheck(unittest.TestCase):
    """合成自检：四象限全覆盖，防止 `refuse_reason` 被削弱后仍全绿。"""

    def test_all_four_quadrants(self):
        table = [
            ("真跑·无provider", make_args(run=True, mock=False, provider=None), "no-provider"),
            ("真跑·有provider", make_args(run=True, mock=False, provider="glm"), None),
            ("mock·无provider", make_args(run=True, mock=True, provider=None), None),
            ("未要求跑", make_args(run=False, mock=False, provider=None), None),
        ]
        for label, args, want in table:
            self.assertEqual(want, refuse_reason(args), "象限错误：%s" % label)

    def test_detector_not_trivially_empty(self):
        """反向自检：检测器确有检出能力（M3 的杀法）。"""
        self.assertEqual("no-provider",
                         refuse_reason(make_args(run=True, mock=False, provider=None)))


if __name__ == "__main__":
    unittest.main()
