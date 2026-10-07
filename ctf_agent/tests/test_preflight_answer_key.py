"""scripts/_preflight.py 的答案表必须与生产同一张跨库表（裁判不分叉）。

背景（2026-10-08）
────────────────
preflight 是「赛前 10 分钟清单」，也是**开赛门禁**：它说能开赛就真能开赛。
但它的两处判题都走的是旧单库口径：

    answers = preset_answers(load_questions("data/questions"))   # 仅 49 条

而生产入口 run.py 早在 2026-10-07 就切到了跨库 `eval.corpus.answer_book()`。
两个裁判口径不一致，会造成**双向假水位**：

  - 假阴性：题确实解对了，真值只写在另一个库的副本上 → 旧表查不到 →
    is_correct 判 False → 门禁报 ✗「链路坏了」，其实能解；
  - 假阳性：自己那题没答案，只剩 is_correct 的全局跨题集合粗筛 →
    提交任意其它题的 flag 也算对 → 门禁报 ✓，实际是错的。

现实现 _preflight._load_answer_key() 统一走 answer_book()。本测试锁死这件事。

顺带纠正一处我自己在上一轮写进去的假水位（2026-10-08 自查发现）：
answer_book / run.py 注释里写「跨库并集 169 条」，那是**「flag 字段非空」**的
口径，其中大量是 sha256 占位串（questions_real 93 道里绝大多数 flag 字段
本身就是 sha256），并非判题可用的答案。实测真值：
    明文答案 54 条 / 有真值 210 条 / 旧单库 preset_answers 49 条。
本测试因此**不锁任何计数**，只锁不变式 —— 计数会漂移，不变式不会。

锁死的不变式
────────────
① 新答案表必须**包含旧单库表的全部 id**（换口径不许丢答案）。
② 新答案表的每个值都是**真明文**而非 sha256 占位串（否则等于把裁判交给哈希）。
③ 源码里不得再出现 `preset_answers(...)` 的**实际调用** —— 用 AST 判定，
   这样文档字符串里为了让后人看懂而写的旧写法不会被误判（text 匹配会假红）。

变异验证（2026-10-08 已做，结果如实记录）
──────────────────────────────────────
  M1  `_load_answer_key` 退回 `preset_answers(单库)` → **1 failed**
      （`test_source_no_longer_calls_preset_answers`，AST 检出）。
      注意：M1 下 ①② 行为层断言**不会红**（旧表自然是旧表的超集）→ 说明源码级
      断言不是多余的装饰，它覆盖的是行为断言留出的盲区。
  M3  `_load_answer_key` 改为返回未过滤的 `flag` 字段（混入 sha256 占位串）
      → **2 failed**（`test_no_sha256_placeholders` + 
      `test_old_values_preserved_when_plaintext`）——被**行为层**抓住，
      证明本测试不是纯文本匹配的橡皮图章。
  两个变异体均已还原，`grep MUTANT` 无残留。

为什么③用 AST 而不是 grep
────────────────────────
docstring 里为了让后人看懂「改了什么」，必然要写出旧写法 `preset_answers(...)`。
用文本匹配会**恒假红**（无论实现是否回退都报红）——一个恒红的守卫等于没守卫。
AST 只看真实 `Call` 节点，文档里的话不算调用。
"""
import ast
import os
import re
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_CTF = os.path.dirname(_HERE)
if _CTF not in sys.path:
    sys.path.insert(0, _CTF)

_PREFLIGHT = os.path.join(_CTF, "scripts", "_preflight.py")

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _old_single_lib_answers():
    """旧口径：只读 data/questions 单库 —— 换口径后必须仍是其超集。"""
    from eval.cases import load_questions, preset_answers
    return preset_answers(load_questions("data/questions"))


class TestPreflightAnswerKey(unittest.TestCase):
    def setUp(self):
        import importlib
        self.pf = importlib.import_module("scripts._preflight")
        self.new = self.pf._load_answer_key()

    # ── ① 不丢答案 ──
    def test_superset_of_old_single_lib(self):
        old = _old_single_lib_answers()
        missing = sorted(set(old) - set(self.new))
        self.assertEqual(missing, [],
                         f"跨库答案表丢了旧单库答案（{len(missing)} 条）：{missing[:10]}")

    def test_old_values_preserved_when_plaintext(self):
        """旧表里是真明文的值，新表必须逐字一致（不许被占位串挤掉）。"""
        old = _old_single_lib_answers()
        changed = sorted(k for k, v in old.items()
                         if not _SHA256_RE.match(str(v)) and self.new.get(k) != v)
        self.assertEqual(changed, [],
                         f"明文答案被改写：{changed[:10]}")

    # ── ② 值是真明文 ──
    def test_no_sha256_placeholders(self):
        placeholders = sorted(k for k, v in self.new.items()
                              if _SHA256_RE.match(str(v or "")))
        self.assertEqual(placeholders, [],
                         f"答案表混入 sha256 占位串：{placeholders[:10]}")

    def test_values_are_nonempty_strings(self):
        bad = sorted(k for k, v in self.new.items()
                     if not isinstance(v, str) or not v.strip())
        self.assertEqual(bad, [], f"答案表存在空/非字符串值：{bad[:10]}")

    # ── ③ 源码不再调用旧 API ──
    def test_source_no_longer_calls_preset_answers(self):
        """AST 级别判定：文档字符串里提及 preset_answers 不算调用。"""
        with open(_PREFLIGHT, encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=_PREFLIGHT)
        calls = [
            n.func.id for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id == "preset_answers"
        ]
        self.assertEqual(calls, [],
                         "preflight 里仍有 preset_answers() 实际调用，"
                         "会退回单库口径（与生产裁判分叉）")

    def test_source_calls_answer_book(self):
        with open(_PREFLIGHT, encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=_PREFLIGHT)
        has = any(
            isinstance(n, ast.Call)
            and ((isinstance(n.func, ast.Name) and n.func.id == "answer_book")
                 or (isinstance(n.func, ast.Attribute) and n.func.attr == "answer_book"))
            for n in ast.walk(tree)
        )
        self.assertTrue(has, "preflight 必须调用 answer_book()（跨库唯一答案表）")


if __name__ == "__main__":
    unittest.main()
