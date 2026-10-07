"""主链 skill 断链修复的端到端回归测试（2026-10-06）

背景：诊断见 logs/mainchain_skill_disconnect_20261006.md ——
`infer_skill_require` 的结果只写进 `self._last_skill_require`（**无读取点**），
主链**从不调用 skill_manager.load()** → skill 永不进 registry →
本仓63 个 skill（含本轮接线的 11 个实证solver）在真实跑批中**不会被自动调用**。

本测试锁死：
① 适配层入参契约：路径类/目录类能构造 params；数值类由**确定性提取器**
   构造（2026-10-07 起，见 tests/test_skill_dispatch_numeric_params.py）；
   拿不到必需参数时一律返回 None（fail-closed——不拿猜测参数制造假失败）；
② 附件解析必须用**精确路径**（全库有 181 道题同名附件冲突，basename 盲找会拿错）；
③ flag 抽取：bytes / str / ToolOutput 三种形态都能提取，无则None（不臆造）；
④ **端到端**：真实题面 ezRSA（真·L2）→ 路由命中 crypto_hastad_broadcast
   → build_params → load 进 registry → registry.run → 命中 flag 且
   sha256 与题面逐字匹配 —— 即「接线真的能兑现为解题能力」；
⑤ 白名单外的 skill 不被自动调用。
"""
import contextlib
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_CTF = os.path.abspath(os.path.join(_HERE, ".."))
if _CTF not in sys.path:
    sys.path.insert(0, _CTF)

EZRSA_JSON = os.path.join(_CTF, "data", "questions_real", "crypto",
                          "real_crypto_ezrsa.json")


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Q:
    """最小题目替身。"""

    def __init__(self, atts, desc="", category="crypto", qid="test"):
        self.attachments = atts
        self.description = desc
        self.category = category
        self.id = qid


@contextlib.contextmanager
def _tmp_atts(*names):
    """在临时目录里造出给定文件名的附件（**内容无关**），退出即清理。

    为什么不用 data/questions_real/_attachments 下的真实附件：
      那批附件被 .gitignore 排除（体积/合规），CI 上根本不存在 ⇒ 任何依赖它的
      用例必然失败 ⇒ 只能被标 ``@pytest.mark.local`` ⇒ **护栏随之在 CI 上脱管**。
      而本文件这些用例验的是「**接线 / 取参路径**」，与附件内容无关，只要
      「路径存在、能打开」即可。故用合成附件，让它们重回 CI 门禁。

    ⚠️ 反面教训：护栏被脱管比护栏失败更危险——2026-10-06 有 6 个 skill
    在 AUTO_CALLABLE 内却缺 iter_candidate_params 分支（Registry 静默不调用），
    正是靠本文件这条通用护栏抓出来的；一旦标 local，同类问题会再次静默。
    """
    with tempfile.TemporaryDirectory() as d:
        paths = []
        for n in names:
            p = os.path.join(d, n)
            sub = os.path.dirname(p)
            if sub:
                os.makedirs(sub, exist_ok=True)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("synthetic attachment for wiring test\n")
            paths.append(p)
        yield paths


class TestSkillDispatchAdapter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.disp = _load(os.path.join(_CTF, "tools", "skill_dispatch.py"),
                         "skill_dispatch")

    def test_path_class_builds_params(self):
        with _tmp_atts("output") as paths:
            q = _Q(list(paths))
            p = self.disp.build_params("crypto_hastad_broadcast", q)
            self.assertIsNotNone(p, "路径类 skill 应能构造 params")
            self.assertEqual(p["path"], paths[0])
            self.assertIn("text", p, "应同时给 text 兼容两种取参风格")

    def test_dir_class_builds_params(self):
        with _tmp_atts("output") as paths:
            q = _Q(list(paths))
            p = self.disp.build_params("crypto_lcg_recover", q)
            self.assertIsNotNone(p)
            self.assertEqual(p["kind"], "dir")
            self.assertTrue(p["dir"])

    def test_unknown_skill_and_unresolvable_input_return_none(self):
        """未知 skill / 拿不到必需参数的场景必须 None（fail-closed，不猜参数）。

        2026-10-07 语义更新：crypto_cycling / crypto_primes_subset /
        crypto_knapsack_mhk 已由**确定性提取器**（tools/skill_dispatch 的
        _NUMERIC_EXTRACTORS）接线，不再是"主链无法可靠构造参数"的一类，
        故移出"永不 can build"的断言。
        但 fail-closed 语义**没有放宽**：给它们一个不含所需数值的题面时，
        仍必须返回 None——绝不用默认值/猜测值去喂 solver 制造假失败。
        （对应的"能提取时真跑出 flag"看 tests/test_skill_dispatch_numeric_params.py）
        """
        att = os.path.join(_CTF, "data", "questions_real", "_attachments",
                           "crypto", "real_crypto_ezrsa", "output")
        q = _Q([att])
        self.assertIsNone(self.disp.build_params("no_such_skill", q))
        self.assertFalse(self.disp.should_auto_call("no_such_skill"),
                         "未知 skill 不应进入自动调用白名单")
        for name in ("crypto_cycling", "crypto_primes_subset",
                     "crypto_knapsack_mhk"):
            self.assertIsNone(
                self.disp.build_params(name, q),
                "%s 在题面不含所需数值参数时必须返回 None（不得拿猜测值 "
                "去调 solver 制造假失败）" % name)

    def test_iter_candidate_params_yields_all_attachments(self):
        """多附件题必须逐个产出候选（实测 ezRSA: task.py 解不出、output 能解出）。"""
        with _tmp_atts("task.py", "output") as (t, o):
            q = _Q([t, o])
            cands = list(self.disp.iter_candidate_params("crypto_hastad_broadcast", q))
            self.assertEqual(len(cands), 2, "应产出 2 个候选")
            self.assertTrue(cands[0]["path"].endswith("task.py"))
            self.assertTrue(cands[1]["path"].endswith("output"))

    def test_iter_candidate_params_yields_dir_class(self):
        """回归护栏（2026-10-07）：目录类必须**在 iter 层面**产出候选。

        背景：一次误编辑把 _DIR_SKILLS 分支整体替换成了 _NUMERIC_SKILLS 分支，
        导致唯一的 B 类目录 skill crypto_lcg_recover 在主链里走到
        ``not in _PATH_SKILLS → return``，**永远不被调用**。
        当时本文件只测了 build_params（仍通过），未覆盖 iter_candidate_params
        的目录分支，所以 1157 个用例全绿也没拦住——故补此用例。
        """
        with _tmp_atts("output") as paths:
            q = _Q(list(paths))
            cands = list(self.disp.iter_candidate_params("crypto_lcg_recover", q))
            self.assertEqual(len(cands), 1, "目录类应产出 1 个候选")
            self.assertEqual(cands[0]["kind"], "dir")
            self.assertTrue(cands[0]["dir"])

    def test_every_allowlisted_skill_yields_a_candidate(self):
        """通用护栏：白名单内 skill 在有附件时必须产出候选（含新增的 C 类之外的 Kir）。

        目的：**将来再往 AUTO_CALLABLE 加 skill 时，若它在 iter_candidate_params
        里没有对应分支（即遗漏接线），本用例会立刻变红**，而不是等到跑批里静默失效。
        数值类的三个需要各自的专属附件，故此处只对其余项做「有附件即有候选」检查。

        ⚠️ 本用例**必须留在 CI 门禁内**（勿标 local）：它验的是接线，与附件内容无关，
        用 `_tmp_atts` 合成附件即可跑。历史上正是靠它抓出 6 个静默失效的 skill。
        """
        with _tmp_atts("output") as paths:
            q = _Q(list(paths))
            numeric = {"crypto_cycling", "crypto_primes_subset",
                       "crypto_knapsack_mhk"}  # 各自需要专属数值附件，另有用例覆盖
            for name in sorted(self.disp.AUTO_CALLABLE - numeric):
                with self.subTest(skill=name):
                    self.assertTrue(
                        list(self.disp.iter_candidate_params(name, q)),
                        "%s 在 AUTO_CALLABLE 内但 iter_candidate_params 无分支 → "
                        "接线遗漏（跑到 Registry 时会静默不调用）" % name)

    def test_iter_candidate_params_empty_for_numeric_class(self):
        q = _Q(["x"])
        self.assertEqual(
            list(self.disp.iter_candidate_params("crypto_cycling", q)), [])

    def test_missing_attachment_yields_none(self):
        q = _Q(["definitely/not/exists.bin"])
        self.assertIsNone(self.disp.build_params("crypto_hastad_broadcast", q))

    def test_extract_flag_from_various_shapes(self):
        import re
        fake_flag = "flag{ABC123}"
        self.assertEqual(
            self.disp.extract_flag(fake_flag.encode()), fake_flag)
        self.assertEqual(self.disp.extract_flag(fake_flag), fake_flag)

        class _TO:
            text = "noise " + fake_flag + " noise"

        self.assertEqual(self.disp.extract_flag(_TO()), fake_flag)
        self.assertIsNone(self.disp.extract_flag("no flag here"))
        self.assertIsNone(self.disp.extract_flag(None))

    def test_first_existing_uses_exact_path_not_basename_glob(self):
        """附件解析必须用精确路径（同名附件冲突实测 181 道题）。"""
        with _tmp_atts("output") as paths:
            q = _Q(["definitely/not/exists.bin"] + list(paths))
            self.assertEqual(self.disp.resolve_first_existing(q), paths[0])


class TestMainChainEndToEnd(unittest.TestCase):
    """端到端：题面 → 路由 → load 进 registry → run → 命中 flag。"""

    @pytest.mark.local
    def test_skill_really_solves_via_registry(self):
        """本轮 11 题之一（ezRSA，真·L2）真跑 registry 路径并校验 sha256。"""
        from tools.registry import ToolRegistry
        from tools.skill_manager import SkillManager
        disp = _load(os.path.join(_CTF, "tools", "skill_dispatch.py"),
                     "skill_dispatch2")

        with open(EZRSA_JSON, encoding="utf-8") as _jf:
            truth = json.load(_jf)["flag_sha256"]
        att = os.path.join(_CTF, "data", "questions_real", "_attachments",
                           "crypto", "real_crypto_ezrsa", "output")
        q = _Q([att])

        name = "crypto_hastad_broadcast"
        self.assertTrue(disp.should_auto_call(name))
        params = disp.build_params(name, q)
        self.assertIsNotNone(params)

        registry = ToolRegistry()
        sm = SkillManager(registry=registry)
        adapter = sm.load(name)          # 真实装载（过 AST 沙箱）
        self.assertIsNotNone(adapter, "skill 应能加载")
        self.assertTrue(registry.has(name), "load 后应注册进 registry")

        import asyncio
        out = asyncio.run(registry.run(name, params))
        flag = disp.extract_flag(out)
        self.assertIsNotNone(flag, "registry.run 应产出可识别的 flag")
        self.assertEqual(hashlib.sha256(flag.encode()).hexdigest(), truth,
                         "端到端解出结果 sha256 应与题面一致")

    def test_main_agent_consumes_last_skill_require(self):
        """回归护栏：主链必须**读取** _last_skill_require（不得再是死字段）。"""
        src_path = os.path.join(_CTF, "core", "main_agent.py")
        with open(src_path, encoding="utf-8") as _f:
            src = _f.read()
        # 统计出现次数：初始化1 + 赋值1 + **至少 1 次读取**
        n = src.count("_last_skill_require")
        self.assertGreaterEqual(
            n, 3,
            "_last_skill_require 出现次数应>=3（初始化+赋值+读取），"
            "当前仅 %d 次——若回到 2 说明又变回死字段" % n)
        # 且必须真正调用 load 与 registry.run
        self.assertIn("skill_dispatch", src, "主链应使用入参适配层")
        self.assertIn("self.skill_manager.load(", src,
                      "主链应调用 skill_manager.load() 把 skill 装进 registry")
        self.assertIn("self.registry.run(_skill_name", src,
                      "主链应通过 registry.run 调用 skill")

    def test_infer_skill_require_returns_skill_name(self):
        """回归护栏：infer_skill_require 必须**返回** skill 名（不得再return None）。

        2026-10-06 实测根因：原实现在三条路径上一律 return None，把命中的
        skill_name 丢弃 → 主链拿不到"该调哪个 skill" → 63 个 skill 永远不会被
        自动调用（断链）。本用例锁死「返回 skill_require 结构体」。
        """
        import os as _os
        from core.prompts import infer_skill_require
        from tools.registry import ToolRegistry
        from tools.skill_manager import SkillManager

        registry = ToolRegistry()
        sm = SkillManager(skills_dir=_os.path.join(_CTF, "skills"),
                          registry=registry)
        sm.discover()
        name = "crypto_hastad_broadcast"
        if name not in sm.list_available():
            self.skipTest("skill 仓库不可用")
        sm.load(name)

        with open(EZRSA_JSON, encoding="utf-8") as _jf:
            desc = json.load(_jf)["description"]

        class _Ctx:
            class question:
                pass

        _Ctx.question.description = desc
        _Ctx.question.attachments = []
        req = infer_skill_require(_Ctx(), {"ability_gap": ["缺少有效攻击路径"]}, sm)
        self.assertIsInstance(req, dict, "必须返回 dict（skill_require）而非 None")
        self.assertEqual(req.get("skill_name"), name,
                         "返回的 skill_require 应含正确 skill_name")

    @pytest.mark.local
    def test_multi_attachment_real_solve_via_iteration(self):
        """端到端（多附件）：逐个附件试探必须能跳过 task.py、解出 output。

        这是本轮实测发现的真实缺陷 —— ezRSA 有两个附件，只试第一个会返回 None。
        """
        import asyncio
        import os as _os
        from tools.registry import ToolRegistry
        from tools.skill_manager import SkillManager
        disp = _load(os.path.join(_CTF, "tools", "skill_dispatch.py"),
                     "skill_dispatch_multi")

        with open(EZRSA_JSON, encoding="utf-8") as _jf:
            truth = json.load(_jf)["flag_sha256"]
        base = os.path.join(_CTF, "data", "questions_real", "_attachments",
                            "crypto", "real_crypto_ezrsa")
        q = _Q([os.path.join(base, "task.py"), os.path.join(base, "output")])

        registry = ToolRegistry()
        sm = SkillManager(skills_dir=os.path.join(_CTF, "skills"),
                          registry=registry)
        sm.discover()
        name = "crypto_hastad_broadcast"
        sm.load(name)

        hit = None
        tried = []
        for params in disp.iter_candidate_params(name, q):
            tried.append(os.path.basename(params["path"]))
            out = asyncio.run(registry.run(name, params))
            f = disp.extract_flag(out)
            if f:
                hit = f
                break
        self.assertEqual(len(tried), 2, "应尝试两个附件（实际 %r）" % tried)
        self.assertIsNotNone(hit, "逐个附件试探后应解出（task.py 解不出、output 能）")
        self.assertEqual(hashlib.sha256(hit.encode()).hexdigest(), truth,
                         "多附件端到端 sha256 应匹配")


if __name__ == "__main__":
    unittest.main(verbosity=2)
