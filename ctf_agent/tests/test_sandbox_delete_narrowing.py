"""AST 沙箱删除类收窄的**安全护栏**测试（2026-10-06）

背景：原`_FORBIDDEN_CALLS` 把 `os.remove/rmdir/unlink` 与 `os.system/exec/spawn`
同列禁止，导致 4 个 skill 永久不可加载（reverse_angr_solver / reverse_router /
reverse_js_methodology / zip_fake_encryption）。实测这些调用**只删自己创建的
临时文件**，属过严误伤。

收窄方案：**不放开全局禁令**，改为「仅当删除目标可判定为自建临时产物时豁免」，
字面量路径 / 用户传入路径**仍然禁止**（fail-closed：无法判定即不放行）。

🔴 本测试是**安全护栏**，锁死以下不变量，任何回退放宽都必须先改这里并说明理由：
 ① 真高危项**永远禁止**：os.system/exec/spawn、os.popen、eval/exec/compile/
    __import__、import subprocess/shutil/ctypes/socket…
 ② 删除类：仅自建临时产物放行；字面量路径、用户传入路径、库内部文件仍禁止。
 ③ 豁免识别须覆盖 4 种真实写法（mkstemp/mkdtemp、NamedTemporaryFile + f.name
    两跳、with as、x + ".fixed" 自建后缀），且**必须含 module 级作用域**
    （多个 skill 的自检在 `if __name__ == "__main__"` 块内）。
"""
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_CTF = os.path.abspath(os.path.join(_HERE, ".."))
if _CTF not in sys.path:
    sys.path.insert(0, _CTF)

from tools.skill_manager import ast_sandbox_check  # noqa: E402


def _check(src):
    return ast_sandbox_check(src)


class TestSandboxHighRiskStillForbidden(unittest.TestCase):
    """① 真高危项永远禁止。"""

    def test_command_execution_forbidden(self):
        for src in (
            "import os\nos.system('rm -rf /')",
            "import os\nos.popen('cat /etc/passwd')",
            "import os\nos.execv('/bin/sh', [])",
            "import os\nos.spawn('x', [])",
        ):
            self.assertFalse(_check(src).passed, "高危命令执行未被拦：%r" % src)

    def test_dynamic_eval_forbidden(self):
        for src in ("eval('1+1')", "exec('x=1')", "compile('1', '', 'eval')",
                    "__import__('os')"):
            self.assertFalse(_check(src).passed, "动态执行未被拦：%r" % src)

    def test_dangerous_imports_forbidden(self):
        for src in ("import subprocess", "import shutil", "import ctypes",
                    "import socket", "import multiprocessing"):
            self.assertFalse(_check(src).passed, "危险导入未被拦：%r" % src)

    def test_shutil_rmtree_still_forbidden(self):
        self.assertFalse(_check("import shutil\nshutil.rmtree('x')").passed,
                         "shutil.rmtree 应仍禁止")


class TestDeleteNarrowing(unittest.TestCase):
    """② 删除类：仅自建临时产物放行，其余仍禁止（fail-closed）。"""

    def test_literal_path_delete_forbidden(self):
        for src in ('import os\nos.unlink("C:/Users/x/important.txt")',
                    'import os\nos.remove("/etc/passwd")',
                    'import os\nos.rmdir("/usr")'):
            self.assertFalse(_check(src).passed,
                             "字面量路径删除应仍被禁：%r" % src)

    def test_user_supplied_path_delete_forbidden(self):
        src = "import os\ndef f(p):\n    os.unlink(p)"
        self.assertFalse(_check(src).passed, "用户传入路径删除应仍被禁")

    def test_self_built_temporary_allowed(self):
        """自建临时产物的 4 种写法应放行。"""
        ok_cases = {
            "mkstemp": "import os, tempfile\np = tempfile.mkstemp()[1]\nos.unlink(p)",
            "mkdtemp": "import os, tempfile\nd = tempfile.mkdtemp()\nos.rmdir(d)",
            "with_named_tmp": (
                "import os, tempfile\n"
                "with tempfile.NamedTemporaryFile(delete=False) as f:\n"
                "    p = f.name\n"
                "os.unlink(p)"
            ),
            "self_built_suffix": (
                "import os\n"
                "def run(path):\n"
                "    fixed = path + '.fixed'\n"
                "    os.remove(fixed)\n"
            ),
        }
        for name, src in ok_cases.items():
            self.assertTrue(_check(src).passed,
                            "自建临时产物应放行（%s）：%r" % (name, _check(src).violations))

    def test_unknown_variable_delete_forbidden(self):
        """fail-closed：来源不明的变量删除仍禁止。"""
        src = "import os\ndef f(x):\n    y = x\n    os.unlink(y)"
        self.assertFalse(_check(src).passed, "来源不明变量应仍被禁（fail-closed）")

    def test_module_scope_temp_delete_allowed(self):
        """module 级（if __name__ 块内）自建临时产物也应放行——实测踩过的坑。"""
        src = (
            "import os, tempfile\n"
            "if __name__ == '__main__':\n"
            "    with tempfile.NamedTemporaryFile(suffix='.bin',\n"
            "                                     delete=False) as f:\n"
            "        f.write(b'x')\n"
            "        p = f.name\n"
            "    os.unlink(p)\n"
        )
        self.assertTrue(_check(src).passed,
                        "module 级自建临时产物应放行：%r" % _check(src).violations)


class TestRealRepoSkillsLoadable(unittest.TestCase):
    """③ 收窄的既定效果：3 个只删临时文件的 skill 现在可加载。"""

    def test_three_temp_only_skills_now_loadable(self):
        from tools.skill_manager import SkillManager
        sm = SkillManager()
        for n in ("reverse_angr_solver", "reverse_router", "zip_fake_encryption"):
            self.assertTrue(sm.load(n),
                            "%s 沙箱收窄后应可加载：%r" % (n, sm.list_failures()))

    def test_popen_skill_still_blocked(self):
        """reverse_js_methodology 含 os.popen（真高危）→ 仍应被拦。"""
        from tools.skill_manager import SkillManager
        sm = SkillManager()
        self.assertFalse(sm.load("reverse_js_methodology"),
                         "os.popen 属真高危，不应因收窄而被放开")


if __name__ == "__main__":
    unittest.main(verbosity=2)
