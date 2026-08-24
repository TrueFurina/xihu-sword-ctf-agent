# FACTS.md · 机器事实源（勿手写，用 `scripts/_facts.py --write` 重新生成）

> 本文件由 `scripts/_facts.py` 从代码与 git 实时采集生成，是协同状态的**单一事实源**。
> 任何文档要引用「租约模式 / G0-G4 落地 / 门禁状态 / HEAD」，一律以本文件为准，不得手写。
> 生成时间由采集脚本输出；手工编辑本文件无效，下次 `--write` 会被覆盖。

## 核心状态（机器采集）

| 状态 | 值 | 采集依据 |
|---|---|---|
| 租约模式 | multi（目录级多写者） | `_lease.py` 是否含 `scopes_conflict` |
| G1 目录级多写者租约 | ✅ 已落地 | 同上（lease_mode == multi） |
| G2 会话唯一 ID 登记 | ✅ 已落地 | `_sign.py` 是否含 `init_session` |
| G3 收尾脚本 | ✅ 已落地 | `_closeout.py` 是否存在 |
| G4 写耦合度聚类 | ✅ 已落地 | `_coupling_cluster.py` 是否含 `cluster_average_linkage` |
| 诚实口径门禁 | ✅ 已落地 | `_honesty_scan.py` 是否存在 |
| 文档一致性门禁 | ✅ 已落地 | `_doc_consistency.py` 是否存在 |
| git 身份绑定（P1-7） | ✅ 已落地 | `_sign.py` 是否含 `bind_author` |
| 声明式任务板（T-09） | ✅ 已落地 | `_task_board.py` 是否存在 |
| Reviewer 验收门禁（T-10） | ✅ 已落地 | `_reviewer_gate.py` 是否存在 |
| 当前 HEAD | `439eb40` | `git rev-parse --short HEAD` |

## 为什么需要本文件

三轮锐评的裁定是「写文档不查证」。根因：文档**手写**状态断言（如「单写者全局租约」），
落地后没回写，就从「诚实说明」漂移成「过时谎言」。本文件让状态**由机器采集、由文档引用**，
从机制上杜绝这类漂移。
