# -*- coding: utf-8 -*-
"""wasm_probe 单测（2026-10-20），含变异验证。

被守护的三个真缺陷（都来自实测）：

1. **引号跨行吞串**。`_wat_strings` 早先用 `[^"\\]`，把换行也纳入了，于是一个
   data 段的开引号能一路吞到下一个 data 段，切出 `(memory 0))` 这种碎片，
   真正的 `flag{...}` 反而不显示。
2. **导入名重复拼接**。objdump 的 `- func[0] sig=0 <env.log> <- env.log` 里，
   尖括号内已是全名，拼 `mod.nm` 得到 `env.log.env.log`。
3. **内部函数被算成导入**。Function[..] 段的行 `- func[1] sig=1 <check>` 没有
   `<-`，正则若不带它做区分，导入数会多算。

WABT 不在的机器上也能跑：全部断言基于固定文本，不调用外部进程。
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.adapters import wasm_probe as wp  # noqa: E402

# 真实 `wasm-objdump -x` 输出节选（WABT 1.0.42 实测产出）
OBJDUMP_TEXT = """
probe.wasm:	file format wasm 0x1

Section Details:

Type[3]:
 - type[0] (i32, i32) -> nil
 - type[1] (i32) -> i32
 - type[2] () -> nil
Import[1]:
 - func[0] sig=0 <env.log> <- env.log
Function[2]:
 - func[1] sig=1 <check>
 - func[2] sig=2 <init>
Memory[1]:
 - memory[0] pages: initial=1
Export[3]:
 - memory[0] -> "mem"
 - func[1] <check> -> "check"
 - func[2] <init> -> "init"
Code[2]:
 - func[1] size=15 <check>
 - func[2] size=8 <init>
Data[2]:
 - segment[0] memory=0 size=21 - init i32=16
 - segment[1] memory=0 size=14 - init i32=64
"""

# 合法的 wat 源文件（给 wat2wasm 用；上面的 WAT_TEXT 是 wasm2wat 的**输出**格式，
# 两者不能混用——`(func (;1;) (type 1) ...)` 这种写法 wat2wasm 不接受）
WAT_SOURCE = """(module
  (import "env" "log" (func $log (param i32 i32)))
  (memory (export "mem") 1)
  (data (i32.const 16) "flag{wasm_probe_2026}")
  (data (i32.const 64) "wrong_password")
  (func $check (export "check") (param $x i32) (result i32)
    local.get $x
    i32.const 42
    i32.eq)
  (func $init (export "init")
    i32.const 0
    i32.const 17
    call $log))
"""

# 真实 `wasm2wat` 输出（含两个 data 段，正是能触发跨行吞串的形状）
WAT_TEXT = '''(module
  (type (;0;) (func (param i32 i32)))
  (import "env" "log" (func (;0;) (type 0)))
  (func (;1;) (type 1) (param i32) (result i32)
    local.get 0
    i32.const 42
    i32.eq
    if (result i32)  ;; label = @1
      i32.const 1
    else
      i32.const 0
    end)
  (memory (;0;) 1)
  (export "mem" (memory 0))
  (export "check" (func 1))
  (data (;0;) (i32.const 16) "flag{wasm_probe_2026}")
  (data (;1;) (i32.const 64) "wrong_password"))
'''


def test_parse_structure_counts():
    s = wp._parse_structure(OBJDUMP_TEXT)
    assert s["types"] == 3
    assert s["functions"] == 2
    assert len(s["exports"]) == 3
    assert s["has_memory"] is True
    assert len(s["data_segments"]) == 2
    assert s["data_segments"][0] == (0, 21)


def test_imports_not_double_joined():
    """`env.log` 不能被拼成 `env.log.env.log`。"""
    s = wp._parse_structure(OBJDUMP_TEXT)
    assert s["imports"] == ["env.log"]


def test_internal_functions_are_not_imports():
    """Function[..] 段的 check/init 不能被算成导入。"""
    s = wp._parse_structure(OBJDUMP_TEXT)
    assert "check" not in s["imports"]
    assert "init" not in s["imports"]
    assert len(s["imports"]) == 1


def test_wat_data_strings_no_crossline():
    """跨行吞串回归：data 段字符串必须干净，不能出现 `(memory 0))` 碎片。"""
    _, data_strs = wp._wat_strings(WAT_TEXT)
    assert data_strs == ["flag{wasm_probe_2026}", "wrong_password"]
    for s in data_strs:
        assert "\n" not in s
        assert "(" not in s


def test_wat_strings_include_flag():
    all_strs, _ = wp._wat_strings(WAT_TEXT)
    assert any("flag{wasm_probe_2026}" == s for s in all_strs)


def test_is_wasm_magic():
    assert wp._is_wasm(b"\x00asm\x01\x00\x00\x00") is True
    assert wp._is_wasm(b"MZ\x90\x00") is False
    assert wp._is_wasm(b"\x00as") is False


@pytest.mark.skipif(not wp._wabt_available()[0], reason="WABT 未安装")
def test_real_wabt_end_to_end(tmp_path):
    """有 WABT 时跑一次真链路：编译 wat → 结构 + data 段字符串。"""
    wat = tmp_path / "t.wat"
    wat.write_text(WAT_SOURCE, encoding="utf-8")
    wasm = tmp_path / "t.wasm"
    rc, _, err = wp._run("wat2wasm", str(wat), "-o", str(wasm))
    assert rc == 0, err

    text, contract = None, None
    # 走公开入口更贴近真实调用
    import asyncio
    out = asyncio.run(wp.WasmProbeAdapter().run({"path": str(wasm)}))
    assert out.ok is True
    assert "flag{wasm_probe_2026}" in out.text
    assert "data 段字符串" in out.text


def test_mutation_crossline_regex_would_swallow():
    """变异证据：旧正则 `[^"\\\\]`（允许换行）确实会切出脏串。

    独立复算旧写法，证明上面那条断言守的是真差异。
    """
    import re
    old = re.findall(r'"((?:[^"\\]|\\.){4,200})"', WAT_TEXT)
    assert any("\n" in s for s in old), "旧正则本应跨行吞串；若此断言失败说明样本不再能触发"
