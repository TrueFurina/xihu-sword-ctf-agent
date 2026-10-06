"""Skill 管理器：动态加载/注册/沙盒校验 CTF 解题技能。

设计原则（赛事安全）：
- 所有 Skill 从本地预置仓库加载，**不发起外网请求**（比赛环境无外网）
- Skill 代码经过 AST 沙盒校验，拒绝含危险操作的脚本
- 加载失败不阻断解题，记录 failure 后继续

Skill 定义：
- 解题技能脚本（专项攻击脚本、工具调用模板、payload 模板）
- 某类题型完整 prompt 片段（密码学小算法、隐写分析流程、Web 绕过范式）
- 注册后成为 ToolRegistry 中的可用工具，MainAgent 可直接调用

目录约定：
    ctf_agent/skills/              # 本地预置 Skill 仓库
    ctf_agent/skills/<name>.py     # 单个 Skill 脚本（必须含 run() 函数）
    ctf_agent/skills/<name>.json   # Skill 元数据（name/purpose/input/output）
"""

from __future__ import annotations

import ast
import importlib.util
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# ── 实证状态分档（2026-08-22 锐评第三节整改）────────────────────────
# 已实证 = 在真题复盘（测试赛 7 题 + 赛后 12 题）里实际用出过 flag 的 skill。
# 依据：data/results/赛后真题复盘-哪些题本可解-20260821.md 第二节 + 第一节。
# 用途：未上场 skill 加载时打 ⚠️ 警告——临场 LLM 加载未验证 skill 比不加载更糟
#       （错误路由消耗墙钟）。决赛前未实证 skill 要么找题验证、要么明确标占位。
VERIFIED_IN_RACE_SKILLS = frozenset({
    # 测试赛 7 题实证（复盘第一节）
    "rsa_fermat_factor",          # 10696 TheoremPlus 自主解出
    "zip_filename_chain_decode",  # 10663 解压缩 自主解出
    "java_nashorn_response",      # 10680 Fate 自主解出
    "pwn_nogdb_flow",             # 10678 easy_uaf 自主解出
    "web_xxe_file_read",          # 10664 UploadKing 并行会话解出
    # 赛后 12 题实证（复盘第二节，工具链离线口径）
    "caesar_bruteforce",          # real_crypto_caesar 0.2s
    "hash_crack",                 # real_crypto_hash_brute 0.2s
    "morse_decoder",              # real_crypto_qiangwang_classic 0.3s
    "base64_multilayer",          # real_crypto_ezmult 12.2s
    "reverse_obfuscation",        # real_reverse_js 0.5s
    "reverse_elf_general",        # real_reverse_sheng/upx
    "zip_chain_decode",           # real_misc_xuanhun_ezip 层1 解出
    "crypto_complex_mult_group",  # real_crypto_specialcurve2 offline_verified 解出（2026-08-24 复核）
})

# 模块级缓存（架构 A2 修复：多路竞速 build_solver 时只读盘/import 一次）──
# 36 个 skill × 3-16 路 solver = 36×N 次重复 I/O；缓存后仅 36 次。
# 注意：module 共享要求 skill 脚本为纯函数式（run(params)->result，无模块级可变状态）
_MODULE_CACHE: dict[str, Any] = {}
_SOURCE_CACHE: dict[str, str] = {}

# ── 安全校验：AST 沙盒 ──────────────────────────────────────────

# 禁止的模块/函数（高危操作）
# 注：`subprocess` 已移出（2026-10-06 改由 _SUBPROCESS_ALLOWED_EXECUTABLES
# 白名单 + 调用形态校验管控，见下方说明），其余仍整体禁止。
_FORBIDDEN_IMPORTS = {
    "shutil", "ctypes", "multiprocessing",
    "socket", "http.server", "xmlrpc",
}
_FORBIDDEN_CALLS = {
    "eval", "exec", "compile", "__import__",
    # 命令执行：列全变体（2026-10-06 补漏——原列表只有 os.exec/os.spawn，
    # `os.execv/execve/execl/execvpe/execlp/execle` 与 `os.spawnv/spawnl/
    # spawnve/posix_spawn` 等**同名变体全部漏过**，等于形同虚设）。
    "os.system", "os.popen",
    "os.exec", "os.execl", "os.execle", "os.execlp", "os.execlpe",
    "os.execv", "os.execve", "os.execvp", "os.execvpe",
    "os.spawn", "os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe",
    "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
    "os.posix_spawn", "os.posix_spawnp",
    # 权限 / 进程 / 环境篡改（2026-10-06 探测补漏，均可造成破坏或提权）
    "os.startfile", "os.kill", "os.setuid", "os.setgid",
    "os.chmod", "os.chown", "os.lchown", "os.chroot",
    # 反序列化 RCE：pickle/dill 可直接执行任意代码。
    # ⚠️ **marshal 不列入禁令**——它是 .pyc 反编译（pyc_decompile skill）的必需
    # 工具，且 marshal.loads 只还原代码对象、不含reduce 钩子，攻击面与 pickle
    # 完全不同。2026-10-06 实测：误禁会导致已接线的 pyc_decompile 加载失败。
    "pickle.loads", "pickle.load", "dill.loads",
    "shutil.rmtree",
}

# 反序列化模块禁止导入（pickle 族；marshal 见上方说明故不在此列）
_FORBIDDEN_IMPORTS |= {"pickle", "cPickle", "dill"}

# ── 受限 subprocess 白名单（2026-10-06）─────────────────────────
# 校验 subprocess.run 时需知道"哪些变量被绑定到白名单程序"，暂存当前 AST。
# （模块级仅在单次 ast_sandbox_check 调用内存活，非跨请求共享状态。）
_TREE_CTX = {"tree": None}
# 背景：`subprocess`整体禁止会让 OCR 类 skill（jpeg_png_embedded /
# misc_grid_resample）永久不可用，而它们调用 **tesseract** 是真实刚需
# （实测本机 tesseract 存在：D:/miniconda3_new/Library/bin/tesseract.exe）。
#
# 折中：**放开 subprocess 这一模块，但只允许执行固定白名单里的二进制**，
# 且校验调用形态安全：
#   1. 必须是 subprocess.run(list, ...) —— 列表参数，不走 shell；
#   2. 列表首元素（可执行文件）basename 必须在 _SUBPROCESS_ALLOWED_EXECUTABLES；
#   3. **禁止 shell=True**（否则可拼接任意命令）；
#   4. 其余元素只能是普通字符串/数字（禁止嵌套 list/dict 等复杂注入面）。
# 这样攻击面被压到「只能调 tesseract，且不能用 shell 拼接」。
_SUBPROCESS_ALLOWED_EXECUTABLES = {"tesseract", "tesseract.exe"}

# ── 删除类调用的**受限豁免**（2026-10-06 收窄）────────────────────
# 背景：`os.remove/rmdir/unlink` 原与 `os.system/exec/spawn` 同列禁止，
# 导致 4 个 skill 永久无法加载（reverse_angr_solver / reverse_router /
# reverse_js_methodology / zip_fake_encryption）。实测它们的删除调用
# **全部只删自己创建的临时文件**（tempfile.NamedTemporaryFile(delete=False)
# 产出的路径，或自己写出的 `x + ".fixed"`），与「删任意用户文件」风险差一个量级。
#
# 收窄策略：**不放开全局禁令**，改为「仅当删除目标可判定为自建临时产物时豁免」：
#   1. 参数是 `tempfile.*` 调用结果（内联）→ 豁免；
#   2. 参数是变量名，且该变量在同一函数内**由 tempfile 赋值** → 豁免；
#   3. 参数是 `<已有字符串>.suffix/.fixed/.tmp` 之类自建后缀拼接 → 豁免。
# 其余（字面量绝对路径、用户传入路径、库内部文件）**仍然禁止**。
_SELF_BUILT_SUFFIXES = (".fixed", ".tmp", ".temp", ".bak")


def _collect_whitebin_vars(tree):
    """收集「被显式赋值为白名单程序路径」的变量名。

    覆盖两种真实写法：
      · `tess = r"D:/.../tesseract.exe"`（字面量赋值）
      · `exe = "tesseract"`（相对名亦可）
    仅当赋值的字符串常量 basename 在白名单内才计入——**来源不明的变量不被信任**
    （fail-closed：若变量来自函数返回值/参数/用户输入，则不予放行）。
    """
    out = set()
    if tree is None:
        return out
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            val = node.value
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                if os.path.basename(val.value).lower() in _SUBPROCESS_ALLOWED_EXECUTABLES:
                    for tgt in node.targets:
                        if isinstance(tgt, ast.Name):
                            out.add(tgt.id)
    return out


def _subprocess_used_safely(tree) -> bool:
    """文件内是否**确有**至少一处安全的 subprocess 调用（受限白名单模式）。

    语义：单独 `import subprocess` 而无受控调用 → 可疑 → 拒绝；
    有 ≥1 处安全调用且**没有**任何不安全调用 → 允许。
    """
    found_safe = False
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if not (isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"):
            continue
        if _check_subprocess_call(node):
            return False  # 存在不安全调用 → 整体拒绝
        found_safe = True
    return found_safe


def _check_subprocess_call(call_node: ast.Call) -> list:
    """校验 subprocess.* 调用的形态是否安全（受限白名单模式）。

    放行条件（全部满足）：
      1. 必须是 `subprocess.run(...)`（不放开 Popen/call/check_output 等）；
      2. 第一个位置参数是 **列表字面量**（不走 shell，天然避免命令拼接）；
      3. 列表首元素（可执行文件）basename 在白名单内（仅 tesseract）；
      4. 没有 `shell=True`；
      5. 列表其余元素均为字符串/数字常量（不接受嵌套结构）。
    其余一律拒绝——fail-closed。
    """
    # ① 只允许 subprocess.run
    fn = call_node.func
    if not (isinstance(fn, ast.Attribute) and fn.attr == "run"):
        return ["subprocess 仅允许 run()（白名单模式）"]
    # ④ 禁止 shell=True
    for kw in call_node.keywords:
        if kw.arg == "shell":
            if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return ["subprocess.run 禁止 shell=True（可拼接任意命令）"]
    # ② 参数必须是列表字面量
    if not call_node.args or not isinstance(call_node.args[0], ast.List):
        return ["subprocess.run 第一个参数必须是列表字面量（不使用 shell）"]
    seq = call_node.args[0].elts
    if not seq:
        return ["subprocess.run 列表为空"]
    # ③ 首元素（可执行文件）须在白名单。
    # 允许两种形态：字符串常量；或变量名——但该变量必须在**同一文件**里
    # 被赋为白名单成员的**字符串常量**（如 `tess = r"D:/.../tesseract.exe"`
    # 或 `_locate_tesseract()` 的返回值场景，见 _collect_whitebin_vars）。
    head = seq[0]
    if isinstance(head, ast.Constant) and isinstance(head.value, str):
        exe_name = os.path.basename(head.value).lower()
    elif isinstance(head, ast.Name):
        allowed = _collect_whitebin_vars(_TREE_CTX.get("tree"))
        if head.id not in allowed:
            return ["subprocess.run 可执行文件变量 %r 未绑定到白名单程序"
                    % head.id]
        return []
    else:
        return ["subprocess.run 可执行文件须为字符串常量或已绑定的白名单变量"]
    if exe_name not in _SUBPROCESS_ALLOWED_EXECUTABLES:
        return ["禁止执行非白名单程序: %r（仅允许 %s）"
                % (exe_name, sorted(_SUBPROCESS_ALLOWED_EXECUTABLES))]
    # ⑤ 其余元素须为字符串/数字常量
    for el in seq[1:]:
        if isinstance(el, ast.Constant) and isinstance(
                el.value, (str, int, float)):
            continue
        return ["subprocess.run 列表元素仅允许字符串/数字常量（拒绝嵌套结构）"]
    return []


def _delete_target_is_self_built(argnode: ast.AST,
                                 tmp_vars: set) -> bool:
    """判断 os.remove/unlink/rmdir 的目标参数是否「自己创建的临时产物」。

    仅放行明确可判定为自建临时文件/目录的删除，**字面量路径与用户传入路径
    一律不放行**（fail-closed：无法判定即视为不可放行）。
    """
    # 形态1: os.unlink(tempfile.mkstemp()[1]) 之类内联
    if isinstance(argnode, ast.Call):
        fname = getattr(argnode.func, "attr", None) or getattr(argnode.func, "id", None)
        if fname in ("mkstemp", "mkdtemp", "NamedTemporaryFile",
                     "TemporaryDirectory"):
            return True
        return False
    # 形态2: 变量在同函数内由 tempfile.* 赋值
    if isinstance(argnode, ast.Name):
        return argnode.id in tmp_vars
    # 形态3: 自建后缀拼接（path + ".fixed"）
    if isinstance(argnode, ast.BinOp) and isinstance(argnode.op, ast.Add):
        for side in (argnode.left, argnode.right):
            if isinstance(side, ast.Constant) and isinstance(side.value, str):
                if side.value.startswith(".") and side.value.lower() in _SELF_BUILT_SUFFIXES:
                    return True
    return False


def _collect_tempfile_vars(fn: ast.AST) -> set:
    """收集函数内「由 tempfile 产出」的变量名。

    需覆盖三种真实写法（本仓 4 个 skill 用到）：
      ① `p = tempfile.mkstemp()[1]` / `d = tempfile.mkdtemp()`  → 直接赋值
      ② `with tempfile.NamedTemporaryFile(...) as f: ... ; p = f.name`
         → 需两跳：先记 with 里的临时文件变量 f，再记 `p = f.name`
      ③ `with tempfile.TemporaryDirectory() as d:` → 直接记d
    """
    out = set()
    tempfile_names = {"mkstemp", "mkdtemp", "NamedTemporaryFile",
                      "TemporaryDirectory"}

    def _is_tempfile_call(node: ast.AST) -> bool:
        return (isinstance(node, ast.Call)
                and (getattr(node.func, "attr", None)
                     or getattr(node.func, "id", None)) in tempfile_names)

    # ① 直接赋值 `p = tempfile.mkstemp()[1]` / `d = tempfile.mkdtemp()`
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign):
            val = node.value
            # 形态 a: p = tempfile.mkstemp()（直接调用）
            if _is_tempfile_call(val):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        out.add(tgt.id)
            # 形态 b: p = tempfile.mkstemp()[1]（mkstemp 返回二元组，取下标 1）
            elif isinstance(val, ast.Subscript) and _is_tempfile_call(val.value):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        out.add(tgt.id)

    # ③ with ... as f（f 为临时文件对象，可后续 f.name 取路径）
    #    必须**先于** ② 执行：`p = f.name` 通常写在 with 块内部，
    #    若单遍按源码顺序遍历，收集到 `p` 时 `f` 尚未入集→ 漏判（实测踩过）。
    for node in ast.walk(fn):
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None and _is_tempfile_call(item.context_expr):
                    if isinstance(item.optional_vars, ast.Name):
                        out.add(item.optional_vars.id)

    # ② 第二跳 `p = f.name`（f 已在 ③ 中收集）
    for node in ast.walk(fn):
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Attribute)
                and node.value.attr == "name"
                and isinstance(node.value.value, ast.Name)
                and node.value.value.id in out):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    out.add(tgt.id)

    # ④ 自建后缀变量：`fixed = path + ".fixed"`（zip_fake_encryption 用法）
    for node in ast.walk(fn):
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.BinOp)
                and isinstance(node.value.op, ast.Add)):
            for side in (node.value.left, node.value.right):
                if (isinstance(side, ast.Constant) and isinstance(side.value, str)
                        and side.value.startswith(".")
                        and side.value.lower() in _SELF_BUILT_SUFFIXES):
                    for tgt in node.targets:
                        if isinstance(tgt, ast.Name):
                            out.add(tgt.id)
    return out


@dataclass
class ASTCheckResult:
    """AST 校验结果。"""
    passed: bool = True
    violations: list = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.passed


def ast_sandbox_check(source: str) -> ASTCheckResult:
    """AST 沙盒校验：检查 Skill 脚本是否含高危操作。

    Args:
        source: Python 源码字符串

    Returns:
        ASTCheckResult（passed=True 表示安全）
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return ASTCheckResult(passed=False, violations=[f"语法错误: {exc}"])

    violations = []
    # 供 subprocess 白名单校验查"哪些变量绑定了白名单程序"
    _TREE_CTX["tree"] = tree

    # fail-closed：先按「作用域」为单位收集各作用域内的 tempfile 变量，
    # 便于判定 os.remove/unlink 的目标是否自建临时产物。
    # 作用域含 **module 级**——本仓多个 skill 的自检代码位于
    # `if __name__ == "__main__":` 块内（属 module 而非 function），
    # 只扫 FunctionDef 会漏判（实测踩过：angr/router 仍 FAIL）。
    scopes = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
            scopes.append(node)
    fn_tmp_vars = {sc: _collect_tempfile_vars(sc) for sc in scopes}

    def _delete_allowed(call_node: ast.Call) -> bool:
        """删除类调用是否落在「自建临时产物」豁免范围。"""
        for fn, tvars in fn_tmp_vars.items():
            for sub in ast.walk(fn):
                if sub is call_node:
                    arg = call_node.args[0] if call_node.args else None
                    if arg is not None and _delete_target_is_self_built(arg, tvars):
                        return True
        return False

    for node in ast.walk(tree):
        # 检查 import 语句
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_module = alias.name.split(".")[0]
                if root_module in _FORBIDDEN_IMPORTS:
                    violations.append(f"禁止导入: {alias.name}")
                elif root_module == "subprocess":
                    # 受限白名单模式：允许 import，但**必须确有受控的调用**。
                    # 单独 import 却不用（或用法不安全）→ 视为可疑，拒绝。
                    if not _subprocess_used_safely(tree):
                        violations.append(
                            "禁止裸import subprocess（受限白名单仅允许"
                            " subprocess.run(列表) 执行 tesseract）")

        elif isinstance(node, ast.ImportFrom):
            if node.module:
                root_module = node.module.split(".")[0]
                if root_module in _FORBIDDEN_IMPORTS:
                    violations.append(f"禁止导入: {node.module}")

        # 检查危险函数调用
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in ("eval", "exec", "compile", "__import__"):
                violations.append(f"禁止调用: {func.id}()")
            elif isinstance(func, ast.Attribute):
                # 检查 os.system / os.popen 等
                if isinstance(func.value, ast.Name):
                    full_name = f"{func.value.id}.{func.attr}"
                    # subprocess 受限白名单（2026-10-06）：仅允许 run(列表) 调
                    # tesseract；Popen/check_output/shell=True/非白名单程序均拒。
                    if full_name.startswith("subprocess."):
                        violations.extend(_check_subprocess_call(node))
                        continue
                    # 删除类调用：仅自建临时产物豁免（2026-10-06 收窄）
                    if full_name in ("os.remove", "os.rmdir", "os.unlink"):
                        if not _delete_allowed(node):
                            violations.append(
                                f"禁止调用: {full_name}()（仅允许删除自建临时文件；"
                                f"删除字面量/用户传入路径仍禁止）")
                        continue
                    if full_name in _FORBIDDEN_CALLS:
                        violations.append(f"禁止调用: {full_name}()")

    return ASTCheckResult(passed=not violations, violations=violations)


# ── Skill 元数据 ─────────────────────────────────────────────────

@dataclass
class SkillMeta:
    """Skill 元数据。"""
    name: str = ""
    purpose: str = ""
    input_spec: str = ""
    output_spec: str = ""
    categories: list = field(default_factory=list)  # 适用题型
    version: str = "1.0"
    loaded: bool = False
    load_error: str = ""


# ── Skill 适配器（注册到 ToolRegistry）──────────────────────────

class SkillAdapter:
    """Skill 适配器：将 Skill 脚本包装为 ToolAdapter 兼容接口。

    加载成功后注册到 ToolRegistry，MainAgent 通过 registry.run(skill_name, params) 调用。
    """

    def __init__(self, meta: SkillMeta, run_fn: Callable) -> None:
        self.meta = meta
        self._run_fn = run_fn

    @property
    def name(self) -> str:
        return self.meta.name

    @property
    def categories(self) -> list:
        return self.meta.categories

    def can_handle(self, category: str) -> bool:
        return category in self.meta.categories or not self.meta.categories

    async def run(self, params: dict) -> Any:
        """执行 Skill 脚本的 run() 函数。"""
        from tools.base import ToolOutput
        try:
            result = self._run_fn(params)
            # 支持同步和异步 run()
            import asyncio
            if asyncio.iscoroutine(result):
                result = await result
            if isinstance(result, str):
                return ToolOutput(text=result, ok=True)
            if isinstance(result, dict):
                return ToolOutput(
                    text=str(result.get("output", result)),
                    ok=bool(result.get("ok", True)),
                )
            return ToolOutput(text=str(result), ok=True)
        except Exception as exc:
            logger.warning("[Skill:%s] 执行异常: %s", self.meta.name, exc)
            return ToolOutput(text=f"Skill 执行异常: {exc}", ok=False)


# ── SkillManager ─────────────────────────────────────────────────

class SkillManager:
    """Skill 管理器：从本地仓库加载 Skill，注册到 ToolRegistry。

    目录结构：
        skills/
        ├── rsa_factoring.py        # Skill 脚本（必须含 def run(params)）
        ├── rsa_factoring.json       # 元数据
        ├── morse_decoder.py
        ├── morse_decoder.json
        └── ...

    用法：
        manager = SkillManager(skills_dir="skills")
        manager.discover()           # 扫描仓库
        manager.load("morse_decoder")  # 加载并注册到 registry
        manager.load_from_requirement(skill_req, registry)  # 从 skill_require 加载
    """

    def __init__(
        self,
        skills_dir: str = "skills",
        registry=None,
    ) -> None:
        self.skills_dir = skills_dir
        self.registry = registry
        self._discovered: dict[str, SkillMeta] = {}
        self._loaded: dict[str, SkillAdapter] = {}
        self._failures: list[dict] = []

    def discover(self) -> list[str]:
        """扫描本地 Skill 仓库，返回可用 Skill 名称列表。"""
        if not os.path.isdir(self.skills_dir):
            logger.info("[SkillManager] 仓库目录不存在: %s", self.skills_dir)
            return []

        names = set()
        for fname in os.listdir(self.skills_dir):
            if fname.endswith(".py"):
                name = fname[:-3]
                if name == "__init__":  # 包标记文件不是 skill
                    continue
                names.add(name)
                meta = self._load_meta(name)
                meta.loaded = False
                self._discovered[name] = meta

        logger.info("[SkillManager] 发现 %d 个 Skill: %s", len(names), sorted(names))
        return sorted(names)

    def load(self, name: str) -> Optional[SkillAdapter]:
        """加载指定 Skill：AST 校验 → 动态导入 → 注册到 ToolRegistry。

        Args:
            name: Skill 名称（对应 skills/<name>.py）

        Returns:
            SkillAdapter（加载成功）或 None（失败）
        """
        if name in self._loaded:
            return self._loaded[name]

        py_path = os.path.join(self.skills_dir, f"{name}.py")
        if not os.path.exists(py_path):
            self._record_failure(name, f"文件不存在: {py_path}")
            return None

        # 1. 读取源码（模块级缓存：多 solver 竞速只读一次）
        source = _SOURCE_CACHE.get(name)
        if source is None:
            try:
                with open(py_path, "r", encoding="utf-8") as f:
                    source = f.read()
                _SOURCE_CACHE[name] = source
            except Exception as exc:
                self._record_failure(name, f"读取失败: {exc}")
                return None

        # 2. AST 沙盒校验
        check = ast_sandbox_check(source)
        if not check.passed:
            self._record_failure(name, f"AST 校验未通过: {check.violations}")
            logger.warning("[Skill:%s] AST 校验失败: %s", name, check.violations)
            return None

        # 3. 动态导入（模块级缓存：同一 skill 只 import 一次）
        module = _MODULE_CACHE.get(name)
        if module is None:
            try:
                spec = importlib.util.spec_from_file_location(f"skill_{name}", py_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                _MODULE_CACHE[name] = module
            except Exception as exc:
                self._record_failure(name, f"导入失败: {exc}")
                return None

        # 4. 检查 run() 函数
        run_fn = getattr(module, "run", None)
        if not callable(run_fn):
            self._record_failure(name, "缺少 run() 函数")
            return None

        # 5. 构造适配器
        meta = self._discovered.get(name) or self._load_meta(name)
        meta.loaded = True
        adapter = SkillAdapter(meta=meta, run_fn=run_fn)
        self._loaded[name] = adapter

        # 6. 注册到 ToolRegistry
        if self.registry is not None:
            self.registry.register(adapter)
            logger.info("[Skill:%s] 已注册到 ToolRegistry", name)

        # 7. 实证状态告警（2026-08-22 锐评第三节整改）：
        #    未在真题/测试赛实证过的 skill 加载时显式标注——临场加载未验证
        #    skill 比不加载更糟（错误路由消耗墙钟），决赛前必须找题验证或标占位。
        if name not in VERIFIED_IN_RACE_SKILLS:
            logger.warning(
                "[Skill:%s] ⚠️ 未实证 skill（从未在真题/测试赛解出记录）——"
                "决赛前需找题验证或明确标注占位，慎用",
                name,
            )
        logger.info("[Skill:%s] 加载成功 (purpose=%s)", name, meta.purpose)
        return adapter

    def load_from_requirement(
        self,
        skill_req: Any,
        registry=None,
    ) -> Optional[SkillAdapter]:
        """从 Agent 的 skill_require 结构体加载 Skill。

        Args:
            skill_req: SkillRequirement 或 dict
            registry: 可选 ToolRegistry（覆盖构造时注入的）

        Returns:
            SkillAdapter 或 None
        """
        if registry is not None:
            self.registry = registry

        name = ""
        if hasattr(skill_req, "skill_name"):
            name = skill_req.skill_name
        elif isinstance(skill_req, dict):
            name = str(skill_req.get("skill_name", ""))

        if not name:
            logger.warning("[SkillManager] skill_require 缺少 skill_name")
            return None

        # 安全检查：拒绝高危 Skill
        risk = ""
        if hasattr(skill_req, "safety_risk"):
            risk = skill_req.safety_risk
        elif isinstance(skill_req, dict):
            risk = str(skill_req.get("safety_risk", "low"))
        if risk == "high":
            self._record_failure(name, "高危 Skill 请求被拒绝")
            logger.warning("[Skill:%s] 高危请求被拒绝", name)
            return None

        return self.load(name)

    def list_available(self) -> list[str]:
        """返回已发现的可用 Skill 名称。"""
        return sorted(self._discovered.keys())

    def list_loaded(self) -> list[str]:
        """返回已加载的 Skill 名称。"""
        return sorted(self._loaded.keys())

    def list_failures(self) -> list[dict]:
        """返回加载失败记录。"""
        return list(self._failures)

    def unverified_skills(self) -> list[str]:
        """返回未实证 skill 列表（2026-08-22 锐评第三节整改）。

        已实证 = 真题/测试赛复盘里实际解出过 flag；未实证 = 从未上场。
        决赛前应对未实证 skill 找题验证或明确标注占位。
        """
        return sorted(
            n for n in self._discovered if n not in VERIFIED_IN_RACE_SKILLS
        )

    def _load_meta(self, name: str) -> SkillMeta:
        """加载 Skill 元数据（从 .json 文件或默认值）。"""
        json_path = os.path.join(self.skills_dir, f"{name}.json")
        meta = SkillMeta(name=name)
        if os.path.exists(json_path):
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                meta.purpose = str(data.get("purpose", ""))
                meta.input_spec = str(data.get("input_spec", ""))
                meta.output_spec = str(data.get("output_spec", ""))
                meta.categories = list(data.get("categories", []))
                meta.version = str(data.get("version", "1.0"))
            except Exception:
                pass
        return meta

    def _record_failure(self, name: str, reason: str) -> None:
        import time as _time
        self._failures.append({
            "skill_name": name,
            "reason": reason,
            "timestamp": _time.strftime("%Y-%m-%dT%H:%M:%S"),
        })
