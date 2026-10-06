"""剩余 11 个孤儿 skill 的「不可接线」护栏（2026-10-06 B 层收口）

背景：B 层接线已实质收口（孤儿 22 → 11，crypto 类清零）。剩余 11 个
**全部卡在「题源缺失」或「安全沙箱」**，不是路由/代码问题：

A. 卡在题源缺失（6 个）—— 目标题附件 MISS / flag_sha256 为空 / 需靶机，
   按纪律**不可实证 → 不接线**：
   · misc_zip_fake_encryption、misc_bigfile_analysis、morse_ab_decode
   · reverse_go_apk、web_target_interact
   另 zip_fake_encryption 同时卡沙箱。
   ⚠️ morse_ab_decode 唯一有sha 的目标题 real_misc_udomctf2022_morse
      经核实是 **L0 送分层**（附件 flag.txt 直含明文答案，sha256 匹配）
      → 即便补上附件，接线也无能力增量。

B. 卡在安全沙箱（5 个）—— AST 沙箱拒绝，SkillManager.load() 直接 FAIL：
   · reverse_angr_solver / reverse_router → os.unlink()
   · reverse_js_methodology → os.unlink() + os.popen()
   · zip_fake_encryption → os.remove()
   · misc_grid_resample / jpeg_png_embedded → import subprocess
   （已逐处核实：os.unlink/os.remove 全在 __main__ 自检或删自己产出的临时
     文件，os.popen 仅探测 node，均非高危 → 疑似沙箱过严，但**改安全策略
     需人工裁决**，AI 不擅自改。）

本测试的作用：**防止后人随手给这些孤儿加 skill_map 键**，造成
「看起来接了、实际跑不通/没真解」的假水位。
若将来题源补齐或沙箱收窄，需同步更新本护栏的ALLOW 清单并附真解证据。
"""
import ast
import os
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_CTF = os.path.abspath(os.path.join(_HERE, ".."))
PROMPTS_PATH = os.path.join(_CTF, "core", "prompts.py")

# 明确不可接线的孤儿（附阻塞原因，见模块 docstring）
NOT_WIRABLE = {
    # A. 题源缺失（附件 MISS / sha256 空 / 需靶机）
    "misc_zip_fake_encryption": "目标题附件 MISS + sha256 空",
    "misc_bigfile_analysis": "附件仅 .md writeup，二进制原题不在库",
    "morse_ab_decode": "唯一有sha 的目标题是 L0 送分层（附件直含明文答案）",
    "reverse_go_apk": "候选题 flag_sha256 全为空",
    "web_target_interact": "需靶机(127.0.0.1:9001/9002) + sha256 空",
    # B. 安全沙箱拒绝（SkillManager.load 会 FAIL）
    "zip_fake_encryption": "AST 沙箱禁 os.remove()",
    "reverse_angr_solver": "AST 沙箱禁 os.unlink()",
    "reverse_router": "AST 沙箱禁 os.unlink()",
    "reverse_js_methodology": "AST 沙箱禁 os.unlink()/os.popen()",
    "misc_grid_resample": "AST 沙箱禁 import subprocess",
    "jpeg_png_embedded": "AST 沙箱禁 import subprocess/shutil",
}


def _skill_map():
    with open(PROMPTS_PATH, encoding="utf-8") as _pf:
        tree = ast.parse(_pf.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == "skill_map":
                    return ast.literal_eval(node.value)
    raise AssertionError("skill_map not found in prompts.py")


class TestNotWirableOrphans(unittest.TestCase):
    def test_not_wirable_orphans_are_not_routed(self):
        """护栏：这11 个孤儿**不得**出现在 skill_map 的任何值里。

        理由：它们或题源不足无法实证、或被 AST 沙箱拒绝加载。
        接线只会制造「看起来有能力、实际跑不通」的假水位。
        """
        targets = set(_skill_map().values())
        wrongly = {k: v for k, v in NOT_WIRABLE.items() if k in targets}
        self.assertEqual(
            wrongly, {},
            "以下孤儿被接线了，但题源不足/被沙箱拒绝，会造假水位：%r\n"
            "若已补齐题源或沙箱已收窄，请在ALLOW 清单登记并附真解证据。" % wrongly)

    def test_sandbox_blocked_skills_really_fail_to_load(self):
        """实证：沙箱类孤儿确实无法被 SkillManager 加载（证明阻塞真实存在）。

        若将来沙箱收窄使它们可加载了，本测试会失败 → 提示更新 NOT_WIRABLE
        的阻塞原因（那时它们可能变为可接线候选）。
        """
        import sys
        if _CTF not in sys.path:
            sys.path.insert(0, _CTF)
        from tools.skill_manager import SkillManager
        sandbox_blocked = [
            "zip_fake_encryption", "reverse_angr_solver", "reverse_router",
            "reverse_js_methodology", "misc_grid_resample", "jpeg_png_embedded",
        ]
        sm = SkillManager()
        loadable = [n for n in sandbox_blocked if sm.load(n)]
        self.assertEqual(
            loadable, [],
            "这些曾被沙箱拒绝的 skill 现在能加载了（沙箱已收窄？）→ "
            "需重新评估能否接线，并更新 NOT_WIRABLE 阻塞原因：%r" % loadable)

    def test_morse_target_is_l0_giveaway(self):
        """诚实护栏：morse_ab_decode 唯一有 sha 的目标题确为 L0 送分层。

        real_misc_udomctf2022_morse 的附件 flag.txt 直含明文答案，
        且 sha256 与题面 flag_sha256 一致 → 属送分层，接线无能力增量。
        """
        import hashlib
        import json
        jpath = os.path.join(_CTF, "data", "questions_real", "misc",
                             "real_misc_udomctf2022_morse.json")
        if not os.path.isfile(jpath):
            self.skipTest("udomctf2022_morse 题面不在库")
        with open(jpath, encoding="utf-8") as _jf:
            d = json.load(_jf)
        att = os.path.join(_CTF, "data", "questions_real", "_attachments", "misc",
                           "real_misc_udomctf2022_morse", "flag.txt")
        if not os.path.isfile(att):
            self.skipTest("udomctf2022_morse 附件不在库")
        with open(att, "rb") as _af:
            raw = _af.read().strip()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), d["flag_sha256"],
                         "附件 flag.txt 与题面真值不符——若题面已修正，"
                         "本护栏需重新评估 morse_ab_decode 的接线价值")


if __name__ == "__main__":
    unittest.main(verbosity=2)
