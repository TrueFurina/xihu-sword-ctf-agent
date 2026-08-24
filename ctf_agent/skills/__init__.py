"""确定性 skill 包（P0-C：沙盒 fallback 直接复用 skill 的确定性攻击脚本）。

每个 skill 模块暴露统一入口：
    run(params: dict) -> 解出的明文 bytes / dict / None

沙盒 AST 白名单已放行 `skills` 导入（见 sandbox/subprocess_executor._ALLOWED_IMPORT_PREFIXES），
crypto/misc/web fallback 脚本可 `from skills.<name> import run` 直接复用，
避免「同一攻击逻辑在 toolkit 模板与 skill 各维护一份」的重复（2026-08-21 P0-C 整改）。
"""
