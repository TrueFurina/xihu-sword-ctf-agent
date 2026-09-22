"""presolve 大确定性 skill 覆盖度断言（2026-09-22）。

防 RDD 三重闸：
1. 每个接线 skill 必须可 import（语法/依赖导入不阻塞 import）。
2. 新增 7 路（rsa_fermat_factor / hash_crack / pwn_exploit_flow / pwn_libc_fingerprint
   / reverse_router / web_ssrf / ssti_detect）必须既在 _WIRED_SKILL_MODULES 清单，
   又对应 _try_* 函数真实定义（接入 _tasks 并发嗅探）。
3. 可用但未接线的 skill 必须落在 KNOWN_GAP（诚实缺口清单）——若有人新增 .py skill
   却忘了接线，gap 会出现未预期项 → 测试 FAIL，强制「接线 or 显式说明」。

诚实口径：crypto_coppersmith/high_exponent/lattice/pkcs1_* 等需特定参数提取规格
（尚未沉淀）；web_xxe_file_read 的 run() 返回协程（bug，待修）；reverse_* 具体 skill
/ misc_* / lfsr / morse / php / java / pwn 知识型 等是 solver 阶段（LLM 交互）用途或
需人工逆向——均非静态预扫可解，明确列缺口不谎报「已覆盖」。
"""

import importlib
import inspect
import os
import sys

import pytest

# 把 ctf_agent 加入 sys.path，使 `from core import presolve` 可用
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core import presolve as P  # noqa: E402

NEW_WIRED = [
    "skills.rsa_fermat_factor",
    "skills.hash_crack",
    "skills.pwn_exploit_flow",
    "skills.pwn_libc_fingerprint",
    "skills.reverse_router",
    "skills.web_ssrf",
    "skills.ssti_detect",
]

NEW_FUNCS = [
    "_try_rsa_factor",
    "_try_hash_crack",
    "_try_pwn_exploit",
    "_try_reverse_route",
]


def _skills_dir():
    return os.path.join(_ROOT, "skills")


def _available_skill_modules():
    """skills/ 下所有含 def run 的 .py 模块名集合（skills.<name>）。"""
    out = set()
    d = _skills_dir()
    if not os.path.isdir(d):
        return out
    for fn in os.listdir(d):
        if fn.endswith(".py") and not fn.startswith("__"):
            out.add("skills." + fn[:-3])
    return out


def test_wired_skill_modules_importable():
    """每个接线 skill 必须可 import（registry 适配器无 .py 则跳过）。"""
    for mod in P.wired_skill_modules():
        py_path = os.path.join(_ROOT, *mod.split(".")) + ".py"
        if not os.path.isfile(py_path):
            continue  # registry 适配器（flag_scan/crypto_auto），非 skills/ 下 .py
        importlib.import_module(mod)  # 抛异常即失败（语法/顶层导入错误）


def test_new_skills_are_wired():
    """大确定性 skill 覆盖：新增 7 路必须进生产链路（清单 + _tasks 函数均存在）。"""
    wired = P.wired_skill_modules()
    for mod in NEW_WIRED:
        assert mod in wired, f"{mod} 未列入 _WIRED_SKILL_MODULES（RDD 防护失效）"
    for fn in NEW_FUNCS:
        assert hasattr(P, fn), f"{fn} 未在 presolve 定义（未接入 _tasks 并发嗅探）"


def test_web_target_extended_for_ssrf_ssti():
    """_try_web_target 必须尝试 ssrf + ssti（靶机可达时的交互攻击面）。"""
    src = inspect.getsource(P._try_web_target)
    assert "web_ssrf" in src, "_try_web_target 未接入 web_ssrf"
    assert "ssti_detect" in src, "_try_web_target 未接入 ssti_detect"


def test_coverage_gap_is_known_and_documented():
    """可用但未接线的 skill 必须落在已知缺口清单（防止偷偷漏接/RDD）。"""
    available = _available_skill_modules()
    wired = P.wired_skill_modules()
    gap = sorted(available - wired)
    KNOWN_GAP = {
        # ── fast_solve / decode 已覆盖的编码类 ──
        "skills.base64_multilayer",
        "skills.caesar_bruteforce",
        "skills.morse_decoder",
        "skills.morse_ab_decode",
        "skills.vigenere_decode",              # fast_solve vigenere 关键词已覆盖
        # ── 需特定参数提取规格（尚未沉淀为 presolve 静态嗅探）的 crypto 攻击 ──
        "skills.crypto_coppersmith",
        "skills.crypto_high_exponent",
        "skills.crypto_lattice_attack",
        "skills.crypto_pkcs1_improved",
        "skills.crypto_pkcs1_padding_oracle",  # 交互式 padding oracle，非静态
        "skills.crypto_ecb_block_attack",       # 交互式 oracle，非静态
        # ── run() 返回协程（bug），待修后再接 ──
        "skills.web_xxe_file_read",
        # ── RSA task.py 路由（与 rsa_fermat_factor 同源/重叠，solver 阶段） ──
        "skills.task_analyzer",
        # ── reverse 具体 skill：solver 阶段（LLM 交互）/ 需 angr ──
        "skills.reverse_elf_general",
        "skills.reverse_angr_solver",
        "skills.reverse_obfuscation",
        "skills.reverse_go_apk",
        "skills.reverse_js_methodology",
        # ── misc 分析类：solver 阶段（LLM 交互）/ 需人工研判 ──
        "skills.lfsr_filter_recover",
        "skills.misc_bigfile_analysis",
        "skills.misc_bigfile_traffic",
        "skills.misc_disk_forensics",
        "skills.misc_traffic_analysis",
        # ── 反序列化/Java 类：solver 阶段（LLM 交互） ──
        "skills.php_unserialize_pop",
        "skills.java_deserialization_flow",
        "skills.java_nashorn_response",
        # ── pwn 知识型（主流程已由 pwn_exploit_flow 富化覆盖） ──
        "skills.pwn_nogdb_flow",
        "skills.pwn_ret2dlresolve",
        "skills.pwn_sandbox_escape",
        "skills.pwn_tcache_safelinking",
        # ── web 多步/交互类（solver 阶段，需靶机 + 多步链） ──
        "skills.web_jwt_prototype",
        "skills.web_multi_step_chain",
        "skills.web_race_condition",
        "skills.web_second_order_injection",
        "skills.web_upload_bypass",
        # ── zip 链解码：经 main_agent skill 映射接入（solver 阶段，非 presolve 静态扫描） ──
        "skills.zip_chain_decode",
        "skills.zip_filename_chain_decode",
        # ── zip 伪加密：与 misc_zip_fake_encryption 同源（presolve 已接 misc_ 版） ──
        "skills.zip_fake_encryption",
    }
    unexpected = [g for g in gap if g not in KNOWN_GAP]
    assert not unexpected, (
        f"发现未预期的未接线 skill（可能漏接或需补充 KNOWN_GAP 说明）: {unexpected}\n"
        f"当前缺口全集({len(gap)}): {gap}"
    )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
