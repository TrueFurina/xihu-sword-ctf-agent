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
_FORBIDDEN_IMPORTS = {
    "subprocess", "shutil", "ctypes", "multiprocessing",
    "socket", "http.server", "xmlrpc",
}
_FORBIDDEN_CALLS = {
    "eval", "exec", "compile", "__import__",
    "os.system", "os.popen", "os.exec", "os.spawn",
    "os.remove", "os.rmdir", "os.unlink",
    "shutil.rmtree",
}


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

    for node in ast.walk(tree):
        # 检查 import 语句
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_module = alias.name.split(".")[0]
                if root_module in _FORBIDDEN_IMPORTS:
                    violations.append(f"禁止导入: {alias.name}")

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
