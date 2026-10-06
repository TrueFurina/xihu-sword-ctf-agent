"""主链 skill 断链修复的端到端回归测试（2026-10-06）

背景：诊断见 logs/mainchain_skill_disconnect_20261006.md ——
`infer_skill_require` 的结果只写进 `self._last_skill_require`（**无读取点**），
主链**从不调用 skill_manager.load()** → skill 永不进 registry →
本仓63 个 skill（含本轮接线的 11 个实证solver）在真实跑批中**不会被自动调用**。

本测试锁死：
① 适配层入参契约：路径类/目录类能构造 params，纯数值类与未知 skill 返回 None
   （fail-closed——不拿猜测参数制造假失败）；
② 附件解析必须用**精确路径**（全库有 181 道题同名附件冲突，basename 盲找会拿错）；
③ flag 抽取：bytes / str / ToolOutput 三种形态都能提取，无则None（不臆造）；
④ **端到端**：真实题面 ezRSA（真·L2）→ 路由命中 crypto_hastad_broadcast
   → build_params → load 进 registry → registry.run → 命中 flag 且
   sha256 与题面逐字匹配 —— 即「接线真的能兑现为解题能力」；
⑤ 白名单外的 skill 不被自动调用。
"""
import hashlib
import importlib.util
import json
import os
import sys
import unittest

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


class TestSkillDispatchAdapter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.disp = _load(os.path.join(_CTF, "tools", "skill_dispatch.py"),
                         "skill_dispatch")

    def test_path_class_builds_params(self):
        att = os.path.join(_CTF, "data", "questions_real", "_attachments",
                           "crypto", "real_crypto_ezrsa", "output")
        q = _Q([att])
        p = self.disp.build_params("crypto_hastad_broadcast", q)
        self.assertIsNotNone(p, "路径类 skill 应能构造 params")
        self.assertEqual(p["path"], att)
        self.assertIn("text", p, "应同时给 text 兼容两种取参风格")

    def test_dir_class_builds_params(self):
        att = os.path.join(_CTF, "data", "questions_real", "_attachments",
                           "crypto", "real_crypto_ezrsa", "output")
        q = _Q([att])
        p = self.disp.build_params("crypto_lcg_recover", q)
        self.assertIsNotNone(p)
        self.assertEqual(p["kind"], "dir")
        self.assertTrue(p["dir"])

    def test_numeric_class_and_unknown_return_none(self):
        """纯数值类与未知 skill 必须返回 None（fail-closed，不猜参数）。"""
        att = os.path.join(_CTF, "data", "questions_real", "_attachments",
                           "crypto", "real_crypto_ezrsa", "output")
        q = _Q([att])
        for name in ("crypto_cycling", "crypto_primes_subset",
                     "crypto_knapsack_mhk", "no_such_skill"):
            self.assertIsNone(self.disp.build_params(name, q),
                              "%s 不应被自动构造参数" % name)
            self.assertFalse(self.disp.should_auto_call(name),
                             "%s 不应进入自动调用白名单" % name)

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
        att = os.path.join(_CTF, "data", "questions_real", "_attachments",
                           "crypto", "real_crypto_ezrsa", "output")
        q = _Q(["definitely/not/exists.bin", att])
        self.assertEqual(self.disp.resolve_first_existing(q), att)


class TestMainChainEndToEnd(unittest.TestCase):
    """端到端：题面 → 路由 → load 进 registry → run → 命中 flag。"""

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
