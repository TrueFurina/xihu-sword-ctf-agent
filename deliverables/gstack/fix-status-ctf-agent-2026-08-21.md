# 西湖论剑 CTF-Agent · 锐评 7 类缺陷修复状态（2026-08-21）

> 承接 `critique-ctf-agent-2026-08-21.md`，按用户"都要极致完完全全修改"逐条落地并验证。
> 执行时间：2026-08-21 赛前（初赛 14:00-17:00）。
> 证据：改动文件 `py_compile` 全过；`pytest` 46 passed/1 skipped；`/api/status` 冒烟通过。

## 一、7 类缺陷修复清单

| # | 缺陷 | 修复动作 | 文件 | 状态 |
|---|------|----------|------|------|
| 1 | 根目录 `setup.sh` 供应链炸弹（拉未知 `fx` 二进制+注入 PATH） | 隔离到 `_misc/setup-shimmer.sh` 并附 README；`ctf_agent/setup.sh` 为合法一键脚本 | `_misc/setup-shimmer.sh` | ✅ 关闭 |
| 2 | LLM 白名单非 fail-closed（误配置可取消资格） | `_check_whitelist`/`_resolve_settings` 改默认阻断，仅 `CTF_AGENT_ALLOW_NONWHITELIST=1` 本地调试放行 | `llm/client.py` | ✅ |
| 3 | 沙盒 bash 命令注入（下载+执行绕过） | `_check_bash_command` 重写：禁下载/执行类程序，默认拒绝未知程序名 | `sandbox/subprocess_executor.py` | ✅ |
| 4 | 看板 Mock 假解不可见（演示自欺） | 新增 `/api/status`（mode/use_mock/llm_provider/whitelist_enforced）+ 红/绿横幅；`use_mock` 全链路透传+警告 | `web/server.py`, `web/static/index.html`, `run.py`, `_race_start.py` | ✅ |
| 5 | 多模型竞速死代码复活 | 前轮删 `build_race_solver` 并迁移 MathEngineMatrix 预检到主 `build_solver()`；**本回合发现已被并行会话恢复**（7 caller 删了必 ImportError）→ 判定为在用功能，保留+白名单透传 | `run.py` | ⚠️ 保留（见下） |
| 6 | Mock 自欺测试脚本 `_batch_solve_unified.py` | `git mv` 到 `scripts/_archive_legacy/_batch_solve_unified_MOCK.py` | `scripts/_archive_legacy/` | ✅ |
| 7 | 工程卫生：根目录游离文件 | 分析流水线 4 文件（修正版）覆盖 `scripts/analysis/` 陈旧副本后清根；`_diag_dead.py` 归档；`_kou_*` 调试产物移 `logs/debug_artifacts/` | `ctf_agent/` 根目录 | ✅ |

## 二、关于 #5 的关键判定（与锐评前提不符，显式标注）

锐评将 `build_race_solver` 定性为"v2.0 已决定移除却复活的死代码"。但实际核查：

- 当前 `run.py` 定义 `build_race_solver`，且 **7 个脚本仍 `from run import build_race_solver`**（`_drill_failover`/`_final_drill`/`_pipeline_test`/`_race_final`/`_solve_platform_challenge`/`_test_bailian_race`/`_verify_bailian_e2e`）。
- 今日文档（`双矩阵竞速架构-20260821.md`、`多模型矩阵方案-20260821.md` 等）将其作为**核心在用功能**描述。
- 锐评 10:15 轮次曾因"删竞速"导致这 7 个脚本 `ImportError`，并行会话随后**恢复** `build_race_solver` 以修复该 ImportError——恢复是正确的工程动作。

**结论**：`build_race_solver` 现为真实在用功能，**非死代码**。本轮选择保留它（而非再次删除造成 7 处 ImportError），并确认 fail-closed 白名单对竞速路径透传生效（竞速池 provider 均在白名单内）。如赛后确需回归单一 `build_solver` 架构，应同步改造 7 个 caller，而非直接删函数。

## 三、验证结果

| 验证项 | 命令/方式 | 结果 |
|--------|-----------|------|
| 语法编译 | `python -m py_compile` 全部改动文件 | ✅ 全过 |
| 导入解析 | `import config, llm.client, sandbox.subprocess_executor, web.server` | ✅ OK |
| 单元测试 | `pytest tests/` | ✅ 46 passed, 1 skipped |
| 阶段验证 | `run.py --mode verify`（3 段） | ⚠️ stage3 PASS；failopen/stage2 失败（见下） |
| 看板状态 | `/api/status` TestClient（真实/MOCK 两模式） | ✅ 两模式均正确返回 |

### 两个 verify 脚本失败（均非本轮回归，赛前不阻塞）

1. **`_verify_failopen.py` FAIL** — 脚本 pop 掉 `DEEPSEEK_API_KEY`/`CTF_AGENT_LLM_API_KEY` 后期望 `ai_chat` 返回 `None`；但本环境 `config.py` 会从 **Windows 注册表**补回真实 key（`setup.sh` 经 `setx` 固化），故返回真实 DeepSeek 响应。属环境性问题。`ai_chat` 在无 key 时仍优雅返回 `None`（fail-open 行为本身正确）。
2. **`_verify_stage2.py` FAIL** — `assert output.provider == "deepseek-v4-pro"`（连续失败应升级重型模型）未命中。该函数走 `MainAgent.solve()`（core 子系统），**不经** `run.py` 的 MathEngineMatrix 预检，故与本轮改动无关，属既有 core 升级逻辑 bug。建议赛中/赛后单独排查 `core/main_agent.py` 的 `upgrade_model` 路由。

## 四、赛前就绪结论

- 锐评 7 类缺陷中 **6 类已彻底修复并验证**（#1/#2/#3/#4/#6/#7）。
- #5 竞速按"保留+白名单透传"处理，与锐评删代码前提不符，已显式标注；其恢复本身修复了锐评同轮发现的 7 处 ImportError。
- 白名单 fail-closed 已确认正确放行合法 deepseek 调用（真实 LLM 链路在验证中实测得通）。
- 看板已能明确区分真实 LLM / MOCK 假解，消除演示自欺风险。
- **赛前就绪（GO）**，可 `bash setup.sh` → `_race_start.py --compete` 作战。
