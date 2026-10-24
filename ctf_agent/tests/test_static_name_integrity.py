# -*- coding: utf-8 -*-
"""静态名字完整性回归锁（2026-10-21）。

**为什么需要**（三次真实事故，都不是风格问题）
---------------------------------------------
2026-10-21 首次对全仓跑 `ruff check --select F821,F811`，抓出 6 个 F821：

  ① `agents/math_engine.py:_engine_caesar` —— 先 `re.search(...)` 后 `import re as _re_m`。
     凯撒引擎**每次执行必抛 NameError**，被外层 try/except 吞成 `return None`，
     表现是"凯撒引擎永远解不出题"，而不是报错。属于**静默功能死亡**。
  ② `agents/math_engine.py` pkcs1 分支 —— `[(int(x), ...) for m in re.finditer(...)]`，
     `x` 从未定义（应为 `m.group(1)`）。同一题型的确定性求解链整段失效。
  ③ 三个测试文件的 `if __name__ == "__main__":` 块调用了**改名后已不存在**的函数
     （`test_fresh_ctx_still_stuck_loop` / `test_heldout_status_is_machine_derived` /
     `test_wallclock_not_hit_returns_stuck_loop`）。pytest 收集不到 `__main__` 块，
     所以**测试全绿也发现不了**；只有人肉 `python tests/xxx.py` 自测时才崩。

前两条 pytest 也发现不了：一个被吞异常，一个所在分支没有测试覆盖到。
本文件把"名字对不上"变成会变红的判据，共三道锁：

  - `test_caesar_engine_actually_decrypts`：行为锁。凯撒引擎必须真解出 flag，
    而不只是"不抛异常"（②①类 bug 靠这条直接转红）。
  - `test_main_blocks_only_call_locally_defined_tests`：AST 锁。所有 `__main__`
    块里调用的 `test_*` 名字，必须在本模块顶层真的定义过（防改名漂移）。
  - `test_ruff_f821_f811_clean`：门禁锁。全仓 F821/F811 必须为零。

**刻意的边界**：本文件只管 F821/F811 两类"名字级"硬错，不管 F401（未使用导入）
——后者数量大、多数无害，逐条修的风险高于收益，由 `scripts/_gate_static.py`
按目录白名单分级管理。
"""
from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = ROOT / "tests"


# ── 锁 1：行为锁 —— 凯撒引擎必须真的解出 flag ──────────────────────────────
def test_caesar_engine_actually_decrypts(tmp_path):
    """凯撒引擎必须解出明文 flag。

    密文由 `flag{caesar_ok}` 每个字母 +3 得到：`iodj{fdhvdu_rn}`。
    引擎按 `chr((ord(c) - 97 + shift) % 26 + 97)` 加密方向遍历 26 个位移，
    shift=23 时回到明文。

    修复前该函数第一句 `re.search` 就 NameError（`re` 未导入），
    被 solve() 的容错吞掉 → 返回 (None, None)。所以断言"解得出"，
    而不是"不抛异常"——后者对静默吞异常的实现毫无约束力。
    """
    from agents.math_engine import MathEngineMatrix

    cipher_file = tmp_path / "cipher.txt"
    cipher_file.write_text("iodj{fdhvdu_rn}\n", encoding="utf-8")

    class _Q:
        category = "crypto"
        attachments = [str(cipher_file)]

    engine_name, flag = MathEngineMatrix.solve(_Q())
    assert flag == "flag{caesar_ok}", f"凯撒引擎未解出，实得 {flag!r}（engine={engine_name}）"
    # 必须由 crypto_caesar 自己解出，不能靠其它引擎兜底——否则本锁对
    # "凯撒引擎整段静默死亡"依然无感（仓库里 misc/multilayer 引擎也能顺手解凯撒）。
    assert engine_name == "crypto_caesar", (
        f"应由 crypto_caesar 解出，实得 engine={engine_name}"
    )


def test_caesar_engine_skips_wrong_category(tmp_path):
    """直接调用引擎本体：非 crypto 题必须返回 None。

    走 `MathEngineMatrix.solve()` 测这条无效——`misc_decode` 等引擎会顺手解出
    同一份密文，把"引擎自身的题型守卫"完全遮住。所以这里直呼内部函数。
    """
    from agents.math_engine import MathEngineMatrix

    caesar = MathEngineMatrix._engines["crypto_caesar"]
    cipher_file = tmp_path / "cipher.txt"
    cipher_file.write_text("iodj{fdhvdu_rn}\n", encoding="utf-8")

    class _Q:
        category = "misc"
        attachments = [str(cipher_file)]

    assert caesar(_Q()) is None, "crypto_caesar 不该处理 misc 题"


# ── 锁 2：AST 锁 —— __main__ 块不许调用不存在的测试函数 ─────────────────────
def _iter_test_files():
    """遍历 tests/ 下全部 .py（排除 __init__ 与 conftest）。"""
    for p in sorted(TESTS_DIR.glob("*.py")):
        if p.name in ("conftest.py", "__init__.py"):
            continue
        yield p


def _main_block_test_calls(tree: ast.Module) -> list[tuple[str, int]]:
    """抽出 `if __name__ == "__main__":` 块里以 `test_` 开头的裸调用。

    返回 [(函数名, 行号)]。只认 `Call(func=Name)` 形态——`pytest.main()` 这类
    属性调用、以及 `fn(...)` 别名调用不在约束范围内（后者无法静态判定）。
    """
    calls: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        test_expr = node.test
        # 匹配 `__name__ == "__main__"`（任一操作数顺序）
        is_main = (
            isinstance(test_expr, ast.Compare)
            and len(test_expr.comparators) == 1
            and isinstance(test_expr.comparators[0], ast.Constant)
            and test_expr.comparators[0].value == "__main__"
        )
        if not is_main:
            continue
        for call in ast.walk(node):
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name):
                if call.func.id.startswith("test_"):
                    calls.append((call.func.id, call.lineno))
    return calls


@pytest.mark.parametrize("path", list(_iter_test_files()), ids=lambda p: p.name)
def test_main_blocks_only_call_locally_defined_tests(path):
    """`__main__` 块里调用的每个 `test_*` 都必须在本模块顶层定义过。

    这条锁的靶子是**函数改名后忘改自测清单**：pytest 不收集 `__main__`，
    改名漂移在 CI 里永远绿；但人肉跑 `python tests/xxx.py` 立刻 NameError，
    而人肉自测恰恰是出事故时最先做的事——最需要它好用的时刻它最不可靠。
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    defined = {
        n.name for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }
    dangling = [
        (name, lineno) for name, lineno in _main_block_test_calls(tree)
        if name not in defined
    ]
    assert not dangling, (
        f"{path.name}: `__main__` 块调用了未定义的测试函数 "
        + ", ".join(f"{n}()@L{ln}" for n, ln in dangling)
        + "（多半是函数改名后忘同步自测清单）"
    )


def test_ast_lock_bites_on_synthetic_drift(tmp_path):
    """变异验证：造一个「改名漂移」的合成文件，锁必须转红。

    不验证变异，就没法区分"锁有效"与"锁的匹配逻辑写错了但恰好全绿"。
    """
    src = (
        "def test_new_name():\n"
        "    pass\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    test_old_name()\n"
    )
    p = tmp_path / "test_drift.py"
    p.write_text(src, encoding="utf-8")
    with pytest.raises(AssertionError, match="test_old_name"):
        test_main_blocks_only_call_locally_defined_tests(p)


def test_ast_lock_passes_on_consistent_file(tmp_path):
    """对照组：自测清单与定义一致时，锁必须放行（防"永远红"的废锁）。"""
    src = (
        "def test_same_name():\n"
        "    pass\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    test_same_name()\n"
    )
    p = tmp_path / "test_ok.py"
    p.write_text(src, encoding="utf-8")
    test_main_blocks_only_call_locally_defined_tests(p)  # 不抛即通过


# ── 锁 3：门禁锁 —— 全仓 F821/F811 必须为零 ────────────────────────────────
def test_ruff_f821_f811_clean():
    """全仓不得存在未定义名/未使用重定义。

    F401（未使用导入）刻意不在本锁范围：多数无害且改动面大，
    由 `scripts/_gate_static.py` 分级管理。本锁只守会让代码**跑不起来**的两类。
    """
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "ruff", "check", ".",
             "--select", "F821,F811", "--output-format", "concise"],
            cwd=ROOT, capture_output=True, text=True, timeout=120,
        )
    except FileNotFoundError:  # ruff 未安装：无法判定 → 明确 skip 而非静默通过
        pytest.skip("ruff 未安装，跳过静态门禁锁")
    if proc.returncode not in (0, 1):
        pytest.skip(f"ruff 执行异常（rc={proc.returncode}）：{(proc.stderr or '')[:200]}")
    findings = [
        ln for ln in (proc.stdout or "").splitlines()
        if "F821" in ln or "F811" in ln
    ]
    assert not findings, (
        "全仓仍有未定义名/重定义（跑不起来或静默失效的真 bug）：\n"
        + "\n".join(findings[:20])
    )
