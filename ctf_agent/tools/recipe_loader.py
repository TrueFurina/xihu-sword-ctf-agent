"""工具声明式配方加载器（2026-09-02，借鉴 SecAutoMind 100+ YAML 工具配方）。

目标：降低加工具成本——新增简单工具只需写一个 JSON 配方（声明式），
自动生成 ToolAdapter 并注册，无需写 Python 类；复杂工具仍用代码式 adapter。

设计（适配项目现状）：
- 配方格式 JSON（非 YAML——PyYAML 未装，零新依赖，与 skills/*.json 一致）
- 配方声明：name / description / command（命令模板，{param} 占位替换）/
  inputs（参数声明）/ categories（题型）
- 执行：subprocess 执行命令模板（参数已替换），stdout 即工具输出；
  命令缺失时降级返回"工具未安装"提示（不误报，与 reverse_angr_solver 同策略）
- 本机工具缺失示例：strings_extract 用 python 内建实现（无外部依赖）

配方目录：tools/tool_recipes/*.json
用法：
    from tools.recipe_loader import load_recipe_adapters
    for a in load_recipe_adapters(): registry.register(a)
"""

import json
import logging
import os
import re
import subprocess

from tools.base import ToolAdapter, ToolOutput

logger = logging.getLogger(__name__)

RECIPES_DIR = os.path.join(os.path.dirname(__file__), "tool_recipes")


class RecipeAdapter(ToolAdapter):
    """从 JSON 配方构造的工具适配器：执行命令模板，参数替换 + 输出清洗。"""

    def __init__(self, recipe: dict, sandbox=None) -> None:
        self.name = str(recipe.get("name", "recipe_tool"))
        self.description = str(recipe.get("description", ""))
        self.categories = list(recipe.get("categories", []))
        self._command = str(recipe.get("command", ""))
        self._inputs = list(recipe.get("inputs", []))
        self._timeout = int(recipe.get("timeout", 30))
        super().__init__(sandbox=sandbox)

    def can_handle(self, category: str) -> bool:
        return category in self.categories or not self.categories

    def _build_cmd(self, params: dict) -> str:
        """按配方 inputs 校验参数并替换命令模板占位。"""
        cmd = self._command
        for inp in self._inputs:
            key = str(inp.get("name", ""))
            val = params.get(key)
            required = bool(inp.get("required", False))
            if val is None:
                if required:
                    raise ValueError(f"配方 {self.name} 缺必需参数: {key}")
                continue
            cmd = cmd.replace("{" + key + "}", str(val))
        # 未替换的占位符（缺参）—— 由调用方参数决定，保留原样执行前检查
        return cmd

    async def run(self, params: dict) -> ToolOutput:
        try:
            cmd = self._build_cmd(params)
        except ValueError as e:
            return ToolOutput(text=f"配方参数错误: {e}", ok=False)
        if not cmd.strip():
            return ToolOutput(text=f"配方 {self.name} 命令为空", ok=False)
        # 执行前检查命令是否存在（Windows 下 first token）
        first = cmd.split()[0].replace('"', "")
        if first.endswith((".py", ".exe")) or os.path.exists(first):
            pass  # 显式路径
        else:
            found = subprocess.run(
                f"where {first} 2>nul" if os.name == "nt" else f"which {first}",
                shell=True, capture_output=True, text=True, timeout=10,
            )
            if found.returncode != 0:
                return ToolOutput(
                    text=f"[{self.name}] 工具未安装: {first}（pip/apt 安装后可用）——降级提示，不误报",
                    ok=False,
                )
        try:
            proc = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                timeout=self._timeout, errors="replace",
            )
            out = (proc.stdout or "")[:4000]
            if not out.strip() and proc.returncode != 0:
                return ToolOutput(text=f"[{self.name}] 执行失败 rc={proc.returncode}: {proc.stderr[:200]}", ok=False)
            return ToolOutput(text=out or f"[{self.name}] 无输出", ok=bool(out.strip()))
        except subprocess.TimeoutExpired:
            return ToolOutput(text=f"[{self.name}] 执行超时（{self._timeout}s）", ok=False)
        except Exception as exc:  # noqa: BLE001
            return ToolOutput(text=f"[{self.name}] 异常: {exc}", ok=False)


def load_recipe_adapters(recipes_dir: str = RECIPES_DIR) -> list:
    """加载 recipes 目录全部 JSON 配方 → RecipeAdapter 列表。"""
    adapters = []
    if not os.path.isdir(recipes_dir):
        return adapters
    for fname in sorted(os.listdir(recipes_dir)):
        if not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(recipes_dir, fname), encoding="utf-8") as f:
                recipe = json.load(f)
            if isinstance(recipe, dict) and recipe.get("name") and recipe.get("command"):
                adapters.append(RecipeAdapter(recipe))
                logger.info("已加载工具配方: %s", recipe.get("name"))
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("配方 %s 加载失败: %s", fname, e)
    return adapters
