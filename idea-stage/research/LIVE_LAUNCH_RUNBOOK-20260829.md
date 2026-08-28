# 开赛一键启动 · live 对战 + race-intelligence（2026-08-29）

> 用途：西湖论剑（或任意 DASCTF 平台比赛窗口）开赛时，一键启动 live 平台对战——
> 拉题 → race-intelligence 动态分配（并发/聚焦）→ 自动解题 → 提交 flag。
> 对应风险①「真实提交待活跃赛题」的落地预案：接线已在 `68fc3a5` 就绪，开赛即可用。

## 一、前提（环境变量，已在系统环境配置）

| 变量 | 值 | 说明 |
|---|---|---|
| `DASCTF_BASE_URL` | `https://pro.dasctf.com` | 平台地址 |
| `DASCTF_TOKEN` | `<平台 Token>` | 鉴权 |
| `CTF_AGENT_LLM_PROVIDER` | `mimo` | 执行器（白名单可用，qwen 网关额度曾 403 已弃用） |

## 二、一键启动

```bash
cd E:\Program\西湖论剑\ctf_agent

# 比赛全程：定时轮询（30s 间隔，Ctrl+C 退出）
python run.py --mode platform --interval 30

# 或单轮（调试/验证用）
python run.py --mode platform --once
```

## 三、race-intelligence 行为（自动启用，无需参数）

- `run.py` platform 模式自动加载 `core/race_orchestrator.RaceController`，**fail-open**：
  控制器缺失/异常 → 降级硬编码并发，不阻塞对战。
- 每轮 `run_once`：`plan(new_ones)` → `Allocation` 覆盖硬编码调度——
  - 并发数 ≤8（`DecisionEngine._optimal_concurrency`）
  - 聚焦题优先排序（边际收益 Top-N 提前启动）
- 控制器不可用时日志：`ℹ️ race-intelligence 控制器不可用（...），降级硬编码调度`

## 四、预期输出

- 汇总行：`处理 N 题 | 解出 X | 提交成功 Y | 失败 Z`
- 每题一行：`✅` accepted / `🔑` 解出未接受 / `❌` 失败（附 detail）
- 解题报告自动生成：`data/reports/解题报告_<时间戳>.md`
- 提交额度熔断（防幻觉耗光额度）：`SUBMIT_FUSE_TOTAL=30` 累计 / `SUBMIT_FUSE_CONSEC=5` 连续失败

## 五、监控

- 平台拉题：`GET .../exercise-list "HTTP/1.1 200 OK"`（0 题=空窗，正常）
- 解题进度：stdout 每步 `[题id]` 日志；比赛形态建议配合 `--interval 30` 常驻

## 六、当前状态（2026-08-29 验证记录）

- 平台可达但 **0 活跃赛题**（赛间空窗）→ 开赛窗口出现题目后本脚本直接可用
- 接线已验证：聚焦排序 ✓ / fail-open ✓ / 真实控制器 ✓ / live 链路 0 题优雅（EXIT=0）✓ / 冒烟 3/3（presolve）✓
- 步级 token 硬停（`457fe15`）同时生效：单题超 cap 立即终止，超调收敛到单次 LLM 调用

## 七、回滚

- 接线代码在 `68fc3a5`（`ctfplatform/poller.py` + `run.py`）：`git revert 68fc3a5` 即回退到纯硬编码调度
- 冒烟/实验数据：`ctf_agent/data/results/claim1/`（本地，gitignore 不入库）
