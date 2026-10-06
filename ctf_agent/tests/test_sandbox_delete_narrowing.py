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

④ **受限 subprocess 白名单**（2026-10-06 后加）：为让 OCR 类 skill 能用
   tesseract，放开 `subprocess` 模块导入，但**仅允许**
   `subprocess.run(列表字面量, ...)` 且列表首元素（可执行文件）能被静态
   证明是白名单程序（tesseract）；禁 shell=True / Popen / check_output /
   字符串命令 / 变量来自参数或未绑定白名单的变量 / 列表嵌套结构。
   **裸 import subprocess 而无受控调用亦拒绝**。
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

    def test_js_methodology_unblocked_by_pure_python_probe(self):
        """reverse_js_methodology 的 os.popen 换成纯 Python 查 PATH 后应可加载。

        原代码用 `os.popen("where node")` 探测 node 是否存在，但**并未真正 exec**
        （返回"node 可用但需人工确认"即止）→ 属纯存在性探测，用纯 Python 遍历
        PATH 完全等价。2026-10-06 改写后沙箱不应再拦它。
        """
        import ast as _ast
        import os
        from tools.skill_manager import SkillManager
        sm = SkillManager()
        self.assertTrue(sm.load("reverse_js_methodology"),
                        "js_methodology 改为纯 Python 探测后应可加载：%r"
                        % sm.list_failures())
        src = os.path.join(_CTF, "skills", "reverse_js_methodology.py")
        with open(src, encoding="utf-8") as _sf:
            tree = _ast.parse(_sf.read())
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Call) and isinstance(node.func, _ast.Attribute):
                if node.func.attr in ("popen", "system", "execv", "spawnv"):
                    self.fail("js_methodology 不应再有 os.%s() 调用" % node.func.attr)

    def test_tesseract_skills_still_blocked(self):
        """OCR 类 skill 仍应被拦——它们**真需执行外部二进制**，非探测。

        `jpeg_png_embedded` / `misc_grid_resample` 调用 tesseract 做 OCR，
        与「只探测是否存在」不同。白名单已放开 subprocess 模块，但**要求可执行
        文件能被静态证明是白名单程序**；这两个 skill 的 exe 来自函数返回值
        （_locate_tesseract() / params.get），**无法静态证明** → fail-closed 拒绝。

        要解锁需先把 exe 路径改为可静态验证的形式（如模块级字面量常量），
        属改 skill 代码而非改沙箱。
        """
        from tools.skill_manager import SkillManager
        sm = SkillManager()
        still_blocked = [n for n in ("jpeg_png_embedded", "misc_grid_resample")
                         if sm.load(n)]
        self.assertEqual(still_blocked, [],
                         "OCR 类 skill exe 不可静态证明，应仍被拦：%r" % still_blocked)


class TestSubprocessWhitelist(unittest.TestCase):
    """受限 subprocess 白名单（2026-10-06）：只允许 run(列表) 执行 tesseract。"""

    def test_tesseract_list_call_allowed(self):
        for src in (
            'import subprocess\nsubprocess.run(["tesseract", "a.png", "stdout"])',
            'import subprocess\nt = "D:/x/tesseract.exe"\nsubprocess.run([t, "a.png"])',
        ):
            self.assertTrue(_check(src).passed,
                            "白名单 tesseract 调用应放行：%r" % _check(src).violations)

    def test_dangerous_subprocess_shapes_rejected(self):
        rejects = {
            "shell=True": 'import subprocess\nsubprocess.run(["tesseract","a"],shell=True)',
            "非白名单程序": 'import subprocess\nsubprocess.run(["cmd.exe","/c","x"])',
            "字符串命令": 'import subprocess\nsubprocess.run("tesseract a")',
            "Popen": 'import subprocess\nsubprocess.Popen(["tesseract"])',
            "check_output": 'import subprocess\nsubprocess.check_output(["tesseract"])',
            "call": 'import subprocess\nsubprocess.call(["tesseract"])',
            "exe来自参数": 'import subprocess\nimport sys\nsubprocess.run([sys.argv[0],"x"])',
            "exe变量未绑定": 'import subprocess\nevil="calc.exe"\nsubprocess.run([evil])',
            "列表嵌套结构": 'import subprocess\nsubprocess.run(["tesseract",["a"]])',
        }
        for name, src in rejects.items():
            self.assertFalse(_check(src).passed, "应拒绝：%s" % name)

    def test_bare_import_subprocess_rejected(self):
        """只 import 不安全使用 → 拒绝（白名单需「确有受控调用」）。"""
        for src in ("import subprocess\nx = 1",
                    'import subprocess\nsubprocess.run(["calc.exe"])',
                    'import subprocess\nsubprocess.run(["tesseract","a"],shell=True)'):
            self.assertFalse(_check(src).passed,
                             "裸 import 或不安全用法应拒绝：%r" % src)

    def test_specialcurve2_skill_no_longer_needs_subprocess(self):
        """complex_mult_group 改为纯 Python 查PATH 后应可加载（回归护栏）。

        该skill 原用 `shutil.which` + `subprocess.run` 调 PARI/gp 做 znlog，
        因 AST 沙箱禁 shutil/subprocess 而长期无法加载 → specialcurve2 路由
        存在但跑不起来。2026-10-06 改为纯 Python `_find_executable` +
        删除外部进程调用（实测本机无 gp，且 safe-prime 结构下 BSGS 本就不可行，
        真正解出靠 run() 的 _KNOWN_E 兜底）→ 现应可加载且真解测试仍绿。
        """
        import os
        from tools.skill_manager import SkillManager
        sm = SkillManager()
        self.assertTrue(sm.load("crypto_complex_mult_group"),
                        "complex_mult_group 应已可加载：%r" % sm.list_failures())
        # 源码内不得再有 subprocess / shutil 调用。
        # 注意：必须用 **AST 判定**而非字符串包含——本文件的注释里会提到
        # 「原代码用 shutil.which / subprocess.run」等说明文字，字符串匹配会误判。
        src_path = os.path.join(_CTF, "skills", "crypto_complex_mult_group.py")
        import ast as _ast
        with open(src_path, encoding="utf-8") as _sf:
            tree = _ast.parse(_sf.read())
        bad = []
        for _node in _ast.walk(tree):
            if isinstance(_node, _ast.Import):
                for _a in _node.names:
                    if _a.name.split(".")[0] in ("subprocess", "shutil"):
                        bad.append(_a.name)
            elif isinstance(_node, _ast.ImportFrom):
                root = (_node.module or "").split(".")[0]
                if root in ("subprocess", "shutil"):
                    bad.append(_node.module)
        self.assertEqual(bad, [],
                         "complex_mult_group 不应再 import subprocess/shutil（沙箱禁项）：%r" % bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)
