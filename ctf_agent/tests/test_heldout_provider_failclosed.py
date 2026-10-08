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

🔴 2026-10-08 二次收口：判定式搬回生产（project memory ㉚ 同型缺陷）
────────────────────────────────────────────────────────
初版把 fail-closed 判定在**本文件**里抄了一份 `refuse_reason()`，理由是「让测试覆盖
行为而不只是源码文本」。动机正当，后果是**护栏看不见生产侧的漂移**：已实测，把生产
`main()` 里的 `not args.mock` 摘掉（`--run --mock` 冒烟也被拦——非常符合本仓「再紧一档」
习惯的改动），本测套仍 **7 passed**。模仿实现的自检验证的是自己那份副本，不是被测入口。

处置：
  1. 生产抽出 `benchmark_heldout.should_refuse(args) -> str | None`，`main()` 改为调用它；
     本文件删除本地副本，全部断言打在这一个函数上。
  2. 新增源码级不变式 `test_main_uses_the_shared_predicate`：用 AST 确认 `main()` 里确有
     对 `should_refuse` 的调用——防止日后有人把判定重新内联回去，护栏再次退化成读副本。
  3. 未知原因码由 `refusal_text()` fail-closed 处理（认不出就拒绝放行，不得静默通过）。

变异验证（两轮，结果如实记录）
────────────────────────────
修之前（生产漂移不可见）：
  漂移  生产守卫去掉 `not args.mock`  → **7 passed**（护栏完全没看见，即本次所补之洞）
修之后（同一漂移重跑）：
  漂移  生产守卫去掉 `not args.mock`  → **2 failed**（`test_mock_run_needs_no_provider`
        + `test_all_four_quadrants`）——同样的改动，只是换谁来判定，结论就从绿变红。
  M1   `should_refuse` 恒返回 None     → 3 failed（CLI 端到端 + 两个合成象限）
  M2   AST 不变式改为恒通过            → 1 failed（合成自检抓住；真实数据上该分支恒绿）
"""

from __future__ import annotations

import ast
import os
import sys
import unittest
from argparse import Namespace
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts import benchmark_heldout as bh  # noqa: E402

_BH_SRC = Path(bh.__file__).resolve()


def predicate(args):
    """唯一判定的入口：**直接调生产函数**。

    本文件此前自持一份副本；那份副本与生产漂移时不会有任何用例变红（已实测 7 passed
    看不见生产把 `--run --mock` 一并拦掉）。现在这里只做转发，不做重述。
    """
    return bh.should_refuse(args)


def make_args(run=False, mock=False, provider=None):
    return Namespace(run=run, mock=mock, provider=provider)


class TestSharedPredicateWiring(unittest.TestCase):
    """源码级不变式：`main()` 必须真的调用共享判定函数。

    这条防的是「把判定重新内联回 main()」——一旦内联，所有行为用例就只能再抄一份副本，
    护栏立刻退化成本文件自我印证。AST 断言比 grep 稳：docstring / 注释里也写着
    `should_refuse` 字样，文本匹配会恒绿。
    """

    def test_main_uses_the_shared_predicate(self):
        tree = ast.parse(_BH_SRC.read_text(encoding="utf-8"))
        mains = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main"]
        self.assertTrue(mains, "benchmark_heldout.py 里找不到 main()")
        calls = {n.func.id for n in ast.walk(mains[0])
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        self.assertIn("should_refuse", calls,
                      "main() 不再调用 should_refuse()——判定被内联了？"
                      "那会让本测套重新变成验证自己的副本（project memory ㉚）")

    def test_no_second_predicate_in_tests(self):
        """本文件不得再生第二份判定式（副本就是漂移的温床）。"""
        own = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        banned = {"refuse_reason"}
        defined = {n.name for n in own.body if isinstance(n, ast.FunctionDef)}
        self.assertFalse(defined & banned,
                         f"本文件又出现了本地判定副本: {sorted(defined & banned)}")

    def test_invariant_detector_is_not_trivially_true(self):
        """AST 检测器自身的合成自检：给一份「未调用」的源码也必须给出否定结论。

        不配合成数据，把断言写成 `assertIn(..., calls or ["should_refuse"])` 这类恒真式
        也不会变红（project memory ⑳/M2：当前自洽的护栏，弱化型变异体必然存活）。
        """
        self.assertTrue(_main_calls_predicate('def main():\n    return 0\n') is False)
        self.assertTrue(_main_calls_predicate('def main():\n    return should_refuse(a)\n')
                        is True)


def _main_calls_predicate(src: str) -> bool:
    """从源码文本判断 main() 是否调用 should_refuse（供自检复用的同一判定逻辑）。"""
    tree = ast.parse(src)
    mains = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main"]
    if not mains:
        return False
    calls = {n.func.id for n in ast.walk(mains[0])
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    return "should_refuse" in calls


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
        """冒烟路径无需 provider，不得被误拦。

        这条正是「生产把 `not args.mock` 摘掉」时唯一会红的用例——而在把判定搬回生产
        之前，它验证的是本文件的副本，生产同样的漂移完全看不见（7 passed）。
        """
        self.assertIsNone(predicate(make_args(run=True, mock=True, provider=None)))

    def test_select_only_is_not_blocked(self):
        """只选题不构成真跑，不得被拦。"""
        self.assertIsNone(predicate(make_args(run=False, mock=False, provider=None)))
        self.assertIsNone(predicate(make_args(run=True, mock=False, provider="glm")))

    def test_env_var_supplies_provider(self):
        """环境变量可作为 provider 来源（保留既有惯例）。"""
        os.environ["CTF_AGENT_LLM_PROVIDER"] = "glm"
        ns = bh.build_arg_parser().parse_args([])
        self.assertEqual("glm", ns.provider)


class TestRefuseReasonSelfCheck(unittest.TestCase):
    """合成自检：四象限全覆盖 + 未知原因码 fail-closed。

    与上一版的差别：**这里跑的是生产函数 `should_refuse`，不是本文件的副本**。
    副本型自检在本轮已被证明形同虚设——生产 float drift（去掉 `not args.mock`）时，
    验证副本的 7 个用例一个都没红。
    """

    def test_all_four_quadrants(self):
        table = [
            ("真跑·无provider", make_args(run=True, mock=False, provider=None), "no-provider"),
            ("真跑·有provider", make_args(run=True, mock=False, provider="glm"), None),
            ("mock·无provider", make_args(run=True, mock=True, provider=None), None),
            ("未要求跑", make_args(run=False, mock=False, provider=None), None),
        ]
        for label, args, want in table:
            self.assertEqual(want, predicate(args), "象限错误：%s" % label)

    def test_detector_not_trivially_empty(self):
        """反向自检：检测器确有检出能力（M1 的杀法）。"""
        self.assertEqual("no-provider",
                         predicate(make_args(run=True, mock=False, provider=None)))

    def test_unknown_reason_code_is_refused_loudly(self):
        """认不出的原因码必须拒绝放行而非静默通过（fail-closed）。"""
        lines = bh.refusal_text("some-unknown-code")
        self.assertTrue(lines and all(isinstance(x, str) for x in lines))
        joined = "\n".join(lines)
        self.assertIn("拒绝放行", joined)
        self.assertNotIn("None", joined[:20])


if __name__ == "__main__":
    unittest.main()
