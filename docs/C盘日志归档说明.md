# C 盘散落日志归档说明（2026-08-28）

> 对应诉求：用户要求"日志也都别堆到 C 盘，关于本项目的所有都放到文件夹下"。

## 1. 实证核查结果

C 盘散落的项目关联 WorkBuddy 全局数据：

| 位置 | 内容 | 体量 |
|---|---|---|
| `C:\Users\Lenovo\.workbuddy\logs\2026-08-XX\西湖论剑__*.log` | WorkBuddy 按项目名自动写的每日会话日志 | 11 天 |
| `C:\Users\Lenovo\.workbuddy\workspace\sessions\<uuid>\modify_backup\` + `.modify_backup_meta\` | 会话编辑备份副本（含本项目文件名） | 跨多会话 |

## 2. 三个关键事实（决定能做什么）

1. **这些是 WorkBuddy 应用自身写的全局数据，不是本项目 agent 产生。** 本项目 agent 运行日志按 AGENTS.md §0/§2/§4 强制写项目内 `logs/`，不会落 C 盘。
2. **WorkBuddy 不支持重定向数据目录**：`settings.json` 中无任何 `dataDir`/`logDir`/`userDataDir` 配置键（已逐项排查）；官方文档 Overview 也未提供该配置项。→ 应用级日志仍会持续写 C 盘 `.workbuddy`，**仓库层无法拦截**。
3. **`.workbuddy` 是跨项目全局数据**（含其他项目的记忆/skills/sessions），不能整体挪进单个项目文件夹。

## 3. 本次归档动作（只读 C 盘，未删原文件）

- `logs/c-drive-archive/daily/` — 11 个每日日志，按日期重命名（`2026-08-21__西湖论剑.log` 等），合计 **445M**（单文件最大 221M @ 8-21，含长会话完整工具输出，属正常体量；仅 1 个 >50M）
- `logs/c-drive-archive/modify_backup/` — 32 个会话备份副本，按 `<session-uuid>/` 分目录保留，合计 **2.4M**
- 总归档 **≈448M**；已向 `.gitignore` 追加 `/logs/` 忽略 → **不污染 git 体积**，但物理上集中在项目文件夹内（满足"项目所有放文件夹下"）

## 4. 为何未删 C 盘原文件

- **个人目录删除属高风险操作**（personal_files_safety：需 warn + 确认 + 小批量 + 回收站），未获明确授权不擅自删。
- `modify_backup` 是 WorkBuddy 会话级恢复数据，移动/删会破坏会话恢复能力，且影响的不止本项目。
- 当日日志（8-28）仍被应用持续写入。

## 5. 可选清理（需你确认后执行）

如需彻底从 C 盘移除历史日志（项目内已有完整归档），先 dry-run 预览：

```bash
find "/c/Users/Lenovo/.workbuddy/logs" -iname "西湖论剑__*.log" -print
```

确认后**改用回收站方式删除**（如 `gio trash` 或 PowerShell `Recycle`），**禁止 `rm -rf`**。
`modify_backup` 不建议删（会话恢复依赖）。

## 6. 未来规则（防复发）

- 本项目 agent 运行日志一律写 `logs/`（AGENTS.md 已强制，pre-commit 结构守卫兜底）。
- 应用级日志（C 盘 `.workbuddy`）无法在仓库层重定向。若坚持彻底不落 C 盘，仅两条路（均影响所有项目，需你授权）：
  - (a) WorkBuddy 设置 / 重装时把全局数据目录改到 E 盘；
  - (b) 关闭 WorkBuddy 后把 `C:\Users\Lenovo\.workbuddy` 符号链接到 E 盘（高风险）。
- **建议**：接受应用级元数据留 C 盘（仅 WorkBuddy 自管），本项目"产出/会话产物"已 100% 收进项目文件夹，符合"关于本项目的所有都放到文件夹下"的核心诉求。

## 7. 安全提示

WorkBuddy 会话日志可能含 API token / flag 明文等敏感信息。归档文件已 `.gitignore` 忽略、**绝不入库**；请勿手动 `git add` 这些日志。
