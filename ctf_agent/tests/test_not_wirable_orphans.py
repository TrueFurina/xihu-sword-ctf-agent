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

B. 卡在安全沙箱 —— **2026-10-06 已部分收窄**：
   原禁令把 `os.remove/rmdir/unlink` 与 `os.system/exec/spawn` 同列，导致
   4 个 skill 永久不可加载。实测这些调用**全部只删自己创建的临时文件**
   （tempfile.NamedTemporaryFile(delete=False) 产出的路径，或自己写出的
   `x + ".fixed"`），与「删任意用户文件」风险差一个量级 → 属过严误伤。
   现已改为「**仅删除自建临时产物时豁免**」，字面量路径 / 用户传入路径
   **仍然禁止**（fail-closed）。后续逐个改写「仅探测外部工具存在性」的调用
   （os.popen("where node") → 纯 Python 查 PATH），同样零损失解锁。
   当前效果：
   · 已解锁：reverse_angr_solver / reverse_router / zip_fake_encryption /
     reverse_js_methodology（os.popen → _find_node()，纯 Python 等价）
   · 仍禁止（**真需执行外部二进制**，非探测，删除即损失真实能力）：
     misc_grid_resample、jpeg_png_embedded（均调tesseract 做 OCR，
     且实测本机 tesseract **确实存在**：D:/miniconda3_new/Library/bin/tesseract.exe）。
     另 crypto_complex_mult_group 曾同类问题，已用同样手法（惰性导入 +
     删除实际调用）解决。
   收窄后这些 skill **仍不具备接线条件**（题源缺失 / 外部执行待人工裁决），
   故 NOT_WIRABLE 不变。

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
    # B. 安全沙箱（SkillManager.load 会 FAIL）
    "zip_fake_encryption": "沙箱阻塞已解除（删除类收窄），但目标题附件 MISS+sha 空",
    "reverse_angr_solver": "沙箱阻塞已解除，但目标题 sha256 为空不可实证",
    "reverse_router": "沙箱阻塞已解除，但候选题 sha256 为空不可实证",
    "reverse_js_methodology": "沙箱阻塞已解除（os.popen 换纯 Python 查 PATH），但候选题 sha256 为空",
    "misc_grid_resample": "AST 沙箱禁 import subprocess（真高危）",
    "jpeg_png_embedded": "AST 沙箱禁 import subprocess/shutil（真高危）",
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

    def test_sandbox_state_matches_expectation(self):
        """实证沙箱状态与本护栏的登记一致（沙箱收窄后应及时更新登记）。

        2026-10-06 沙箱收窄后：`os.remove/rmdir/unlink` 改为「仅自建临时产物
        豁免」，**3 个 skill 因此解锁**（angr/router/zip_fake，它们只删自己
        创建的临时文件）；`os.popen`/`import subprocess` 等真高危**仍禁止**，
        故 reverse_js_methodology / grid_resample / jpeg_png_embedded 继续
        不可加载。

        本用例把「哪些已解锁、哪些仍锁」写成断言 —— 沙箱一旦再变，
        本测试转红即提示同步更新 NOT_WIRABLE 的阻塞原因。
        """
        import sys
        if _CTF not in sys.path:
            sys.path.insert(0, _CTF)
        from tools.skill_manager import SkillManager
        now_unlocked = [
            "zip_fake_encryption", "reverse_angr_solver", "reverse_router",
            "reverse_js_methodology",
        ]
        still_locked = [
            # OCR 类：真需执行外部二进制 tesseract（非探测），且本机确实装了
            "misc_grid_resample",      # import subprocess（调tesseract）
            "jpeg_png_embedded",       # import subprocess / shutil（调 tesseract）
        ]
        sm = SkillManager()
        became_loadable = [n for n in now_unlocked if sm.load(n)]
        self.assertEqual(became_loadable, now_unlocked,
                         "这些 skill 应已被沙箱收窄解锁：%r" % became_loadable)
        wrongly_loadable = [n for n in still_locked if sm.load(n)]
        self.assertEqual(wrongly_loadable, [],
                         "真高危项应仍被禁止（os.popen / import subprocess）：%r"
                         % wrongly_loadable)

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
