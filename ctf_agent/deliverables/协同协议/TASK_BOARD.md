# TASK_BOARD.md · 任务板（开工必登记的唯一登记处）

> **协调者维护** · 各会话开工前先读本文件，认领任务后把「任务 id + 文件域 + 预计耗时」写进下表再开工。
> **认领 = 承诺**：门禁绿 + 完工报告。本文件是任务板的唯一权威，协议《多智能体协同协议》§三 的内嵌表格是历史快照，以本文件为准。

## 任务状态机

```
backlog → ready → claimed → in_progress → review → done
               └→ blocked ──────────────┘
               └→ cancelled
```

认领协议（乐观并发，无锁）：两个会话同时认领同一任务时，git 的 non-fast-forward 拒绝天然判定「后提交者失败」，失败方 pull --rebase 后重读本文件再认领（最多 3 次）。对应 GNAP 的 task-claim-race 先例。

## 认领规则（三条硬约束）

1. **先登记再开工**：写任何 tracked 文件前，先在本表登记任务 + 文件域，再 acquire 租约。
2. **文件域必须登记**：任务的文件域（scope）写清楚，与 `_lease.py` 的租约 scope 一致，不得 broad scope 偷懒。
3. **状态如实更新**：任务状态（⬜待办 / 🔄进行中 / ✅完成）随进度更新，完工后标注「门禁绿 + 完工报告」。

## 当前任务表

| 任务 id | 内容 | 文件域（scope） | 状态 | 占用会话 |
|---------|------|----------------|------|----------|
| T-07 | e2e 平台验证（决赛前必跑） | `scripts/_e2e_verify.py` | ⏸ 搁置（平台关，40403） | 协调者 |
| T-09 | 声明式任务板落地（`_task_board.py` + tests） | `scripts/_task_board.py` + `tests/test_task_board.py` | ✅ 完成（7 用例） | gu |
| T-10 | Reviewer 验收门禁落地（merge 前 pytest+scope+honesty 三查） | `scripts/_reviewer_gate.py` + `tests/test_reviewer_gate.py` | ✅ 完成（4 用例） | gu |
| T-11 | git 身份绑定（commit author 绑定 session，修 P1-7 脱钩） | `scripts/_sign.py` + pre-commit | ✅ 完成（bind + ④门禁） | gu |
| T-12 | 诚实化整改收口（solved_by 路径拆分） | `eval/benchmark.py` `core/main_agent.py` `run.py` | ✅ 完成（已由并发会话 a903c28 接管提交，走 `[无任务]` 车道流程） | gu |

## 已归档任务（历史快照）

- 早期 T-01~T-08 任务见协议《多智能体协同协议-20260822》§三 内嵌表格（门禁修复 / 解题攻坚 / 答辩三件套等），其中 T-01/T-02/T-06/T-08 已收口，其余已被后续工作替代。

---

*本文件是「开工必登记」铁律（纲领 §3）的登记载体。任何会话开工前必须先在此登记，否则 pre-commit 的租约门禁无法追溯「谁在写什么」。*
