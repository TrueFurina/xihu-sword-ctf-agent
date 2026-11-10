# CTF-Agent 开赛就绪清单（Go-Live Checklist）

> 生成日期：2026-11-10 ｜ 基于 `audit-xihu-git/ctf_agent`（git `bd1f581`，branch `main`）
> 用途：从"备战/加固态"切换到**真实 CTF 对战**前的逐项门禁。全部打勾 = 可 `run.py --mode platform` 冲一血。

## 一、当前实测状态（已核实）

| 项 | 状态 | 证据 |
|----|------|------|
| 代码库健康 | ✅ 绿 | `pytest -m "not slow and not local"` → `2113 passed, 136 skipped, 80 deselected, 0 failed`（3 轮中 2 轮全绿；1 轮单 `F` 与 safe-delete 假红同发且不复现） |
| 离线核心单测 | ✅ 34 项 0 失败 | 反幻觉 10 + 答案密钥/题型归一/看板持久化 24 |
| 作战看板 | ✅ 在线 | `http://127.0.0.1:8000/`（端口 8000 监听）；启动 `python run.py --mode web` |
| 历史战绩 | ⚠️ 真实解出 = 0 | `goal_log.jsonl` 601 条中 65 个 `flag` 非空**全是练习 `flag{ok}`**；reverse 0/48、misc 0/34 |
| P1 空转恢复 | ✅ 已落地 | `core/main_agent.py` `_apply_reason_loop_fallback`；34 项离线单测覆盖 |
| P2 反幻觉闸门 | ✅ 已证满足 | `extract_flag` 四分支过 sha256 仲裁/`provenance_allows`；数据侧 `validated` 全 False、零 flag 泄漏 |

## 二、开赛前必须补齐（阻塞项）

### B1 · 赛事凭证（platform 模式硬依赖）
- [ ] `DASCTF_BASE_URL` 填入（`.env` 当前为空）
- [ ] `DASCTF_TOKEN` 填入（或 `CTF_AGENT_PLATFORM_TOKEN` 统一 token）
- 校验：`python run.py --mode platform --once` 能拉到题 → 进入解题→提交闭环

### B2 · 多 Provider LLM Key（并发抢分的前提）
- [ ] 当前仅 `ZHIPU_API_KEY`(glm-4-flash) 存活，其余（QWEN/DEEPSEEK/MOONSHOT/BAIDU/ARK）为空
- [ ] 至少再补 1 个可用 Provider，推荐优先级（结合余额/免费情况）：千帆 ernie-3.5 > MiMo > tokenhub / xfyun / 百炼
- [ ] 经 `llm-gateway.dasctf.com` 网关路由验证各 Provider 可达（参考 `core/llm_wrapper.py` + `model_registry.py`）
- 校验：`python run.py --mock` 可跑；切真实 key 后 `core/llm_wrapper.py` 单测不过网关即报错

### B3 · P0 附件/靶机注入（HARDENING_BACKLOG P0）
- [ ] harness 须把 `attachments` / `target` **真实注入** agent 上下文（`core/main_agent.py` 空转恢复块依赖此）
- [ ] 无附件且无靶机时**结构化早退**，不进入推理（避免烧 80k token 空转）
- 校验：真实带附件 crypto 题回归；纯推理空转（原 107 条）应显著下降

### B4 · P3 reverse / misc 技能覆盖（当前 0 解出）
- [ ] reverse 专用探针 + 技能（0/48）
- [ ] misc 专用探针 + 技能（0/34）
- 校验：`goal_log` 按题型统计 reverse/misc 解出数 > 0

## 三、赛前彩排（可选但建议）

- [ ] `slow` 套件手动跑（依赖真实附件/在线 LLM/墙钟，~40–70min 机器时间）：`pytest -q -m slow --timeout=900`
  - 其中 `presolve` 主入口默认墙钟 300s，enigma 单路需 598s → 跑它要 `CTF_AGENT_PRESOLVE_WALLCLOCK=900`
  - 2 条 `web_target_wiring` 因附件永久丢失按设计 skip（10-20 数据事故，非回归）
- [ ] `local` 套件（依赖 `.gitignore` 排除的本地真值产物 `REAL_SOLVES_LEDGER.md` / `data/questions_real/_attachments/`）仅本机有，CI 排除

## 四、已知误报（勿误判为回归）

- ⚠️ **safe-delete 守卫假红**：会话结束批量删 tmp 被拒（`SAFE_DELETE_BULK_CONFIRM_REQUIRED` count>50）会使 pytest **EXIT=1 即便全部用例通过**，并可能冲掉 summary 行。属 `pytest.ini` 明示的已知假红，不影响用例结论。
- ⚠️ `benchmark_report.json` 标注 `mode: "mock"`、"`mock 数字禁止引用`"——mock 结果不可对外引用。
- ⚠️ `submitted_flags.json` 的 18 条均为同一题 `x2/solve me` 的 `flag{ok}`，是练习自跑循环，非真实提交。

## 五、启动命令速查

```bash
# 看板（已在线则跳过）
python run.py --mode web
# Mock 自检（无需 key）
python run.py --mock
# 真实对战（需 B1+B2 就绪）
python run.py --mode platform          # 持续拉题→解题→提交
python run.py --mode platform --once   # 单轮验证接线
# 全量验证脚本
python run.py --verify
# 离线测试基线
pytest -q -m "not slow and not local"
```
