r"""确定性能力台账护栏（2026-10-07）

背景（为什么要这个测试）
────────────────────────
主链「路由 → 适配层构造参数 → registry.run → extract_flag」这条确定性兜底链路，
全库真实兑现 **8 题**（sha256 与题库真值逐字匹配，假阳 0）。
但这 8 题里只有 2 题（cycling / primes）有测试覆盖，其余 6 题只被一次性
审计脚本 `scripts/_audit_autocallable_coverage.py` 覆盖 —— 而审计脚本
**不在 CI 里**。于是形成了一个真实缺口：

  - 我曾误删 `iter_candidate_params` 的 `_DIR_SKILLS` 分支，导致唯一的目录类
    skill `crypto_lcg_recover` 在主链里**永不调用**；当时 1157 个用例全绿，
    没有任何测试拦住 —— 因为它只测了 `build_params`，没测 iter 的目录分支。
  - `extract_flag` 的贪婪正则、flag 前缀截断（`csawctf{...}`）也都是同类：
    solver 解对了，但交付层把它判成错 flag。

这类缺陷的共同点是「**能力静默消失**」：没有报错、没有红测试，只是分数悄悄变低。
本测试就是针对它的专用护栏。

锁死什么
────────
① 台账里的每一题，走**与主链完全相同的路径**（`SkillManager.load` →
   `iter_candidate_params` → `registry.run` → `extract_flag`）仍能解出，
   且 sha256 与题库真值逐字相等。
② 台账里的 skill 必须仍在自动调用白名单内（`should_auto_call`），
   防止有人把白名单收窄导致能力被静默摘除。
③ 台账 id 必须在跨库择优后的语料里找得到（防题被改名/移动后台账空转）。

诚实边界
────────
- 这里断言的是「**不退化**」，不是「能力有多少」。新增能力不靠改这个测试，
  靠 `scripts/_audit_autocallable_coverage.py` 实测后**手工**加进 LEDGER。
- 慢题由 `CTF_AGENT_SLOW_TESTS=1` 启用。实测耗时（本机，负载会放大 2~3 倍）：
  cycling ~22s / mhk2 ~79s / primes ~36s（空载）→ 三题归慢；
  默认只跑快题 5 道（ezrsa/filterrandom/simplelegendre/lcg/qr，合计 ~7s）。

变异验证（已做）
──────────────
- **M1** 删掉 `iter_candidate_params` 的 `_DIR_SKILLS` 分支 → 1 failed
  （`lcg` 报 no_candidate_params）—— 本测试的核心靶子，即我曾真实引入的回归。
- **M2** 白名单摘掉 `crypto_lcg_recover` → 2 failed
  （护栏② + 端到端同时抓到）。
- **M3** 把 `_FLAG_RE` 改回贪婪 → **存活（等价变异体）**：现行正则用 `[^}\s]`
  已排除 `}` 本身，贪婪与非贪婪结果相同，不构成威胁，如实记录。
- **M3b** 把 flag 前缀上限从 20 缩到 4（复刻 `csawctf{...}` 截断 bug）→ 2 failed。
"""
import asyncio
import hashlib
import os
import sys
import time
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_CTF = os.path.abspath(os.path.join(_HERE, ".."))
if _CTF not in sys.path:
    sys.path.insert(0, _CTF)

SLOW = os.environ.get("CTF_AGENT_SLOW_TESTS") == "1"

# ── 能力台账：(question_id, skill_name, 是否慢题) ────────────────────────
# 每条都必须经 `scripts/_audit_autocallable_coverage.py` 实测 sha256 匹配后才可加入。
# 严禁凭"应该能解"就往里塞 —— 那正是本仓库反复出现的水分来源。
LEDGER = (
    ("real_crypto_ezrsa", "crypto_hastad_broadcast", False),
    ("real_crypto_filterrandom", "lfsr_filter_recover", False),
    ("real_crypto_simplelegendre", "crypto_legendre_phi", False),
    ("ext_gctf2022_cycling", "crypto_cycling", True),
    ("ext_gctf2023_least-common-genominator", "crypto_lcg_recover", False),
    ("ext_gctf2023_mhk2", "crypto_knapsack_mhk", True),
    ("ext_gctf2023_primes", "crypto_primes_subset", True),
    ("ext_nyu_ctf_bench_2023q_for_1black0white", "misc_qr_matrix", False),
)


def _sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _looks_like_sha256(v):
    import re
    return bool(v) and bool(re.fullmatch(r"[0-9a-f]{64}", str(v)))


def truth_sha(q):
    """题目真值的 sha256：优先 flag_sha256 字段，退化用明文 flag（排除占位串）。"""
    fs = getattr(q, "flag_sha256", None)
    if fs:
        return str(fs)
    fl = getattr(q, "flag", None)
    if fl and not _looks_like_sha256(fl):
        return _sha(str(fl))
    return None


def _corpus_index():
    from eval.corpus import load_corpus
    return {getattr(e.question, "id", ""): e for e in load_corpus()}


class _LedgerSolveTest(unittest.TestCase):
    """台账每题：走主链同款路径真解 + sha256 逐字匹配。"""

    @classmethod
    def setUpClass(cls):
        from tools.skill_manager import SkillManager
        from tools.registry import ToolRegistry
        cls.registry = ToolRegistry()
        cls.sm = SkillManager(registry=cls.registry)
        cls.sm.discover()
        cls.index = _corpus_index()

    def _solve(self, qid, skill_name):
        """返回 (flag, None) 或 (None, 失败原因)。"""
        from tools.skill_dispatch import iter_candidate_params, extract_flag

        entry = self.index.get(qid)
        if entry is None:
            return None, "语料中找不到该 id（题被改名/移动？）"
        q = entry.question
        try:
            self.sm.load(skill_name)
        except Exception as e:  # noqa: BLE001
            return None, "load_failed: %s: %s" % (type(e).__name__, e)
        if not self.registry.get(skill_name):
            return None, "not_registered（skill 未被注册进 registry）"

        last_out = None
        n_cand = 0
        for params in iter_candidate_params(skill_name, q):
            n_cand += 1
            try:
                out = asyncio.run(asyncio.wait_for(
                    self.registry.run(skill_name, params), timeout=180))
            except asyncio.TimeoutError:
                return None, "timeout"
            except Exception as e:  # noqa: BLE001
                return None, "run 异常 %s: %s" % (type(e).__name__, str(e)[:80])
            flag = extract_flag(out)
            if flag:
                return flag, None
            t = getattr(out, "text", None)
            last_out = (t if isinstance(t, str) else str(out))[:120]
        if n_cand == 0:
            return None, ("no_candidate_params（适配层一个候选都没产出 —— "
                          "典型回归：iter_candidate_params 的分支被删）")
        return None, "no_flag; last_out=%s" % last_out

    def test_ledger_ids_exist_in_corpus(self):
        """③ 台账 id 必须在跨库择优语料里存在（防空转）。"""
        missing = [qid for qid, _s, _slow in LEDGER if qid not in self.index]
        self.assertEqual(missing, [], "台账 id 在语料中缺失: %s" % missing)

    def test_ledger_skills_are_auto_callable(self):
        """② 台账 skill 必须仍在自动调用白名单内（防白名单收窄摘能力）。"""
        from tools.skill_dispatch import should_auto_call
        out = [s for _q, s, _slow in LEDGER if not should_auto_call(s)]
        self.assertEqual(out, [], "以下 skill 已不在自动调用白名单: %s" % out)


def _make_solve_test(qid, skill_name, slow):
    def _test(self):
        t0 = time.time()
        flag, err = self._solve(qid, skill_name)
        self.assertIsNotNone(
            flag,
            "台账题 %s 未能解出（%s）—— 这是能力退化，不是测试噪音" % (qid, err))
        q = self.index[qid].question
        truth = truth_sha(q)
        self.assertIsNotNone(truth, "题目 %s 无可用真值，无法校验" % qid)
        self.assertEqual(
            _sha(flag), truth,
            "台账题 %s 解出 flag 但与真值不符（假阳）" % qid)
        # 慢题打印耗时，便于观察性能退化
        if slow:
            print("\n    [%s] %.1fs" % (qid, time.time() - t0))

    _test.__name__ = "test_solve_%s" % qid.replace("-", "_").replace(".", "_")
    if slow:
        _test = unittest.skipUnless(SLOW, "慢题，CTF_AGENT_SLOW_TESTS=1 启用")(_test)
    return _test


for _qid, _skill, _slow in LEDGER:
    _name = "test_solve_%s" % _qid.replace("-", "_").replace(".", "_")
    _t = _make_solve_test(_qid, _skill, _slow)
    _t.__name__ = _name  # skipUnless 包装后 __name__ 会被改掉，显式钉回
    setattr(_LedgerSolveTest, _name, _t)


if __name__ == "__main__":
    unittest.main(verbosity=2)
