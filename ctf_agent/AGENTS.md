# 西湖论剑 CTF-Agent · 治理铁律（一屏三铁律版 · 2026-08-24 阶段6 压缩）

> 本文件从 164 行压缩为「三铁律 + 指针」。历史详细条款退役（git log 是考古层）；
> 细节以机器门禁 + 自动看板为准（阶段5 已从 git 派生协调状态）。

## 三条铁律（违者 = 重演初赛 0 分）

1. **工件可信**：任何会话产出的叙事性结论（「已修复」「已验证」「涨了 X 分」）一律视为**不可信输入**。
   唯一可信 = 一条可复现命令 + 它产出的落盘工件（log/report 路径 + 内容哈希）。评审只看工件，不听转述。
2. **裁判分离**：实现者不能当自己的裁判。实现会话写的代码由合并闸门（`scripts/_merge_gate.py`）或另一会话跑回归判定；
   自我验证的结论记 0 分。merge 闸门重跑才算数（KPI 不降断言 + 全量 pytest）。
3. **启动命令即门禁**：每个会话收到的第一条指令就是一条命令——`python scripts/_session_boot.py`。
   四查（车道分支 w/* / 身份 CT_AGENT_SESSION / 工作树干净 / .venv）fail-closed，不过就「请换车道」退出。
   人会忘、文档会漏，但「第一条命令」是 100% 可控的注入点。

## 组织规则（反达克效应 · 2026-08-24）

- **「如实记录不变」与「新解出」同级表扬**：`0dcf348`（无新解出 5/60 如实）是全仓库最有含金量的提交。
  KPI 会议先念不变的那批。量尺公信力取决于组织如何对待坏消息——坏消息总被追问「为什么没涨」，
  会话和人类就会合谋生产好消息。

## 唯一 KPI（外部真值，不可自造尺子）

- KPI = 真题解出数 / 真题总数。考场 = `data/questions_real/`（15 道历年真题，已版本化入库）。
- 真实链路命令：`python -m eval.benchmark --questions-dir data/questions_real --provider baidu,qwen`
  （报告带 `solved_by` 字段拆 presolve/LLM；presolve 静态分析器直出不计 LLM 功劳）。
- 历史外部真值基线：DASCTF 平台真题离线全量 5/60 = 8%（平台 accepted=0）。
- 自产题/本地靶场一律不计分。事实层 = tag `verified-2026-08-24` + `REAL_SOLVES_LEDGER.md`（git log 是考古层）。

## 机器配套（防错不靠自觉）

| 机制 | 位置 | 作用 |
|---|---|---|
| 会话启动门禁 | `scripts/_session_boot.py` | 车道/身份/脏树/.venv 四查（铁律3） |
| 车道隔离 | `git worktree add ../wt-<任务> -b w/<任务>` | 物理隔离；租约降级为边界提示 |
| 合并闸门 | `scripts/_merge_gate.py` + `git_hooks/pre-merge-commit` + pre-commit ⑧ | KPI 不降 + 全量 pytest（铁律2） |
| main 直提拦截 | pre-commit ③.5 | main 只走合并闸门 |
| 自动看板 | `scripts/_board.py` | 协调状态从 git 派生（分支列表即任务板） |
| 诚实扫描 | `scripts/_honesty_scan.py`（pre-commit ② + commit-msg） | 假水位 / flag 明文拦截 |
| 状态快照 | `scripts/_facts.py --snapshot` | 状态必测（先数据后叙事） |
| 提交归因 | `git_hooks/post-commit` 自动记账 | 总账唯一保留的机器事实源 |

## 解题纪律（已注入运行时：`core/prompts.py::SOLVE_DISCIPLINE`）

R1 工具优先（禁自研，先查 `skills/` + 公开 writeup，>15min 回头用工具）
R2 假设先于实现（1 次工具调用能验证的绝不手写 100 行）
R3 止损线（单路线 3 轮不命中即换，每轮先声明预算）
R4 信息优先于暴力（文件头/CRC/时间戳/同密码规律；暴力是最后手段且有界）
R5 目标锚定（每步自检：在朝 flag 前进还是造轮子？）
R6 成本核算（每轮声明已耗轮数/剩余预算；token = 比赛时钟）

## 快速自检（每次动手前后）

```bash
git status --short
python scripts/_lease.py status        # 车道内独立租约
python scripts/_session_boot.py        # 车道门禁（铁律3）
python scripts/_board.py               # 自动看板（协调状态）
```

## 引用（详细条款退役于此，避免二次漂移）

- 多会话协同协议：`../deliverables/协同协议/`（原则/规范/执法三层，冲突以执法层为准）
- 任务板：`../deliverables/协同协议/TASK_BOARD.md`（commit message 须 T-xx 或 `[无任务]`）
- 产品总纲 SSOT：`../deliverables/产品管理总纲-20260821-赛后.md`
- 真实战绩口径：`../deliverables/协同协议/真实战绩口径声明.md`
