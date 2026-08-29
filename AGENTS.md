# AGENTS.md — 西湖论剑 CTF-Agent 协作与目录法规模约

> 本文件是**所有 AI 协作者（含未来会话/子 agent）的强制约定**。先读后写。
> 与之配套的机器执法：`ctf_agent/scripts/_structure_guard.py`（pre-commit 自动拦截 + `scripts/check_structure.py` 手动自检）。
>
> **⚠️ 核心治理铁律（三铁律/KPI/门禁机制）见 `ctf_agent/AGENTS.md`**——本文件只管目录放置规则，
> 工件可信/裁判分离/启动门禁等治理红线以 `ctf_agent/AGENTS.md` 为唯一真值，开工前必读两份。

## 0. 一句话原则

**任何产出都必须落进"对应的子目录"，禁止在仓库根、`deliverables/` 根、`idea-stage/` 根平铺文件。**
日志/产物一律留在项目文件夹内，**绝不写到 C 盘用户目录（Desktop/Downloads/`C:\Users\Lenovo\.workbuddy\logs` 等）**。

## 1. 目录分类（写文件前先对表）

| 目录 | 归谁 | 示例内容 |
|---|---|---|
| `ctf_agent/` | 核心代码（git 仓库，自有门禁） | agent / scheduler / scripts / tests |
| `data/` | 数据集（真标题/自产训练） | `questions_real/`、`questions/` |
| `idea-stage/` | **科研/idea 管线产物** | `IDEA_REPORT.md`、`refine-logs/`（提案+实验计划）、`proposals/`、`research/`、`research-wiki/` |
| `deliverables/` | **工程/运营交付物**（本地不入库） | `复盘赛报/` `治理协议/` `工程补丁/` `锐评质检/` `规划手册/` `可视化看板/` `归档_禁用引用/` |
| `docs/` | 项目元文档/索引 | `_INDEX.md`、结构说明 |
| `logs/` | 一切 agent 运行日志（**项目内**） | 跑批记录、自检输出 |
| `research-wiki/`（已并入 `idea-stage/research-wiki/`） | — | — |
| `_archive/` `_tools_ghidra/` `recovered_external`（已并入 `_archive/recovered_external/`） | 归档/工具/恢复材料 | 大型，勿动 |
| 根目录仅允许 | `README.md` `README.zh.md` `CLAUDE.md` `LICENSE` `AGENTS.md` `REAL_SOLVES_LEDGER.md` `requirements.txt` `协同任务总账-TOP0.md`（根级白名单由 `ctf_agent/scripts/_structure_guard.py:ROOT_ALLOW` 机器校验，文档与代码一致）| 其余一律禁止 |

## 2. 硬规则（违反即被 pre-commit 拒绝）

1. **禁止根级平铺**：仓库根只允许 `README.md` / `README.zh.md` / `CLAUDE.md` / `LICENSE` / `AGENTS.md` / `REAL_SOLVES_LEDGER.md` / `requirements.txt` / `协同任务总账-TOP0.md`（白名单以 `ctf_agent/scripts/_structure_guard.py:ROOT_ALLOW` 为唯一真值）。任何其他 `*.md/*.txt/*.html/*.json/...` 一律进对应子目录。
2. **禁止 `deliverables/` 平铺**：交付物必须进 `deliverables/` 的 7 个子目录之一（唯一例外 `deliverables/overview.md`）。
3. **禁止 `idea-stage/` 平铺**：科研产物进 `proposals/` `research/` `refine-logs/` `research-wiki/`；根层仅留 `IDEA_REPORT.md` 与已放置的评估文件。
4. **日志不出项目**：所有运行日志写 `logs/`（或 `.workbuddy/memory/` 这种项目内目录），**禁止**写 `C:\Users\Lenovo\...`、`Desktop`、`Downloads`。
5. **先在对应目录建文件，不要先根目录再挪**：根目录只是"误写高发区"。

## 3. 机器执法（本机制就是你要的"防止再堆积的东西"）

- **提交时**：`pre-commit` 钩子（激活位 `ctf_agent/git_hooks/pre-commit`，源 `ctf_agent/scripts/hooks/pre-commit`）末尾第 ⑪ 节调用 `scripts/_structure_guard.py`，对**本次新增文件**（`--diff-filter=A`）做结构校验；命中散落即 `exit 1` 阻断提交（fail-closed）。脚本自带 try/except，自身异常时 fail-open（不误伤正常提交）。
- **手动/CI 自检**：
  ```bash
  python scripts/check_structure.py            # 仅本次新增（与 pre-commit 同口径）
  python scripts/check_structure.py --all      # 全量扫磁盘（含被 .gitignore 忽略的堆积）
  ```
  返回 0 = 合规，1 = 发现散落（并打印归位建议）。

## 4. 日志落盘约定

- 新增 `logs/` 目录专门收纳跑批/自检/会话产物。
- 项目内 `.workbuddy/memory/` 已是项目文件夹内，合规。
- **C 盘 `C:\Users\Lenovo\.workbuddy\logs/`、`workspace/sessions/.../modify_backup/` 等是 WorkBuddy 全局应用数据，由应用自身管理**；若你希望把全局日志也挪到项目内，需要改 WorkBuddy 的全局数据位置设置（非本仓库脚本可控），届时再单独处理。

### 4.1 已从 C 盘回收的归档（2026-08-28）

- `logs/c-drive-archive/daily/` — 11 个每日会话日志（按日期重命名），合计 445M
- `logs/c-drive-archive/modify_backup/` — 32 个会话备份副本（按 `<session-uuid>/` 分目录），合计 2.4M
- 总 ≈448M；`.gitignore` 已加 `/logs/` 忽略，**不入库、不污染 git**，但物理集中在项目文件夹（满足"项目所有放文件夹下"）
- 来源 / 为何不删 C 盘原文件 / 可选清理步骤：见 `docs/C盘日志归档说明.md`
- ⚠️ 这些日志可能含 token/flag 明文，已 gitignore，**禁止手动 `git add`**

## 5. 接手人速记

- 找不到该放哪 → 先问，别先堆根目录。
- 改完跑一遍 `python scripts/check_structure.py --all`，绿了再提交。
- 既有散落历史（如早期根目录 md）已在 2026-08-28 整理中归位；本文件与钩子用于防止**复发**。
