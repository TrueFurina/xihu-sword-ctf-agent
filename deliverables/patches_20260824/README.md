# 收口补丁交付说明（2026-08-24）

## 背景
用户指令："都要完完全全进行修改，同时注意并发会话的操作"。
四件事中三件已完成（真题集实测 / TOP-0 总账 KPI 同步 / MEMORY.md 清理）。
第四件"工作树收口（把 4 个修复合入 main）"在实操中遇到**两个不可绕行的并发/仓库级卡点**，故改为**标准 patch 交付**，待协调器在条件满足后由正常 `w/` 车道合入。

## 本目录补丁清单（已在隔离 worktree 验证通过）
| 补丁 | 内容 | 来源 | 验证 |
|---|---|---|---|
| `benchmark_multiprovider_fix.patch` | `eval/benchmark.py` 每 provider 重新 `load_questions`，消除 `_PRESOLVE_ATTEMPTED` 跨 provider 污染 → 归因干净（还原 robust/union 口径） | 孤儿 commit `f7a41c4` | `git apply` 干净；`tests/test_benchmark_real_chain.py` + `test_eval_integrity.py` + `test_import_smoke.py` + `test_lease.py` 全绿 |
| `crypto_complex_mult_group_json_add.patch` | 新增 `skills/crypto_complex_mult_group.json`（复数乘法群 RSA 解密 skill 描述文件，main 缺失） | 工作树未跟踪文件 | `git apply` 干净 |

> 注：原 4 文件修复中，presolve.py / crypto_complex_mult_group.py / skill_manager.py 三者在 **main 上已存在**（已被其他车道合入或本来就在），无需重复。仅上述两块为增量。

## 合入前置条件（必须遵守，否则制造并发事故）
1. **仓库 ref 写入损坏**：主仓库 `git branch` / `git update-ref` / `git worktree add -b` 全部静默失败（exit 0 但不写 ref），`HEAD`→`w/research-specialcurve2-route-fix` 与 main 的 ancestry 链断裂。需先修复 ref 系统（疑似 Windows 文件锁 / 同步盘落盘问题，其他并发会话正持 `.git` 锁）才能建 `w/` 车道。
2. **租约冲突**：
   - `crypto_complex_mult_group.json` 位于 `skills/` 下，**当前租约 `research-expert-specialcurve2` 持有 `skills/` 整片 scope** → 禁止无授权提交，会撞车。
   - `benchmark.py` 位于 `eval/`，为**无主区域**（无任何会话 claim），租约门禁对无主文件拒绝提交 → 需协调器显式分配 `eval/` 租约给执行会话，或 research-expert 会话确认 eval/ 不在其职责内后由协调器放行。
3. **门禁**：合入须走 `w/` 车道 + `_merge_gate.py`（KPI 不降断言 + verify_10733 真跑 + 全量 pytest `-m "not slow"`），禁止直提 main。

## 应用方式（条件满足后）
```bash
cd E:/Program/西湖论剑/ctf_agent
git worktree add -b w/gu-land-0824c <path> main   # 需仓库 ref 修复后才可行
cd <path>
git apply /path/to/benchmark_multiprovider_fix.patch
git apply /path/to/crypto_complex_mult_group_json_add.patch
git add eval/benchmark.py skills/crypto_complex_mult_group.json
export CT_AGENT_SESSION=<被分配的会话名>
git commit -m "SW-QWEN1: benchmark 多provider重load修复 + crypto skill json [无任务]"
# 走 _merge_gate.py 合入 main
```

## 风险评估
- **不强行合入**：强行 `git checkout -f main` 或 `--allow-unrelated-histories` 会摧毁 `research-expert-specialcurve2` 等会话在 `core/ skills/ tools/` 的未跟踪在途工作（519+ 文件），违背"注意并发会话操作"铁律。
- **数据零丢失**：孤儿 commit `24008b0` / `f7a41c4` 仍可被 `git cat-file` 解析；本 patch 已固化交付物，修复内容不依赖损坏的 ref。
