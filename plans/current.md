# 当前计划（2026-10-01 重建；2026-10-03 / 2026-10-05 / 2026-10-08 更新）

> 依据：2026-10-01 磁盘实测（非记忆/转述）。项目定位＝**非竞赛的工程/能力项目**（确定性优先 CTF 静态分析框架 + 可迁移治理资产）。
> 相关约束见 `.workbuddy/memory/MEMORY.md`；终局复盘见 `deliverables/锐评质检/西湖论剑-项目终局复盘-20260923.md`。
>
> **🔄 2026-10-03 更新摘要**：① D 层 canonical 注释漂移已修（`6790751`，`heldout_candidates` 注释 10→2）；② presolve **B 组假命中治理**完成（`7859665` 实现 + `5c70e76` 测试）——三池 B 组假命中 **11→1**、A 组真命中不变；③ 未推送提交已由 **6 → 22**，逐条核验**全部属他人会话**；④ **10733 缺口已补齐**（`11e3d05`）——从归档+原始 URL 恢复元数据/附件并建语料条目，**台账-语料漂移 1→0**，`real_corpus` **92→93**；⑤ **Google CTF 扩池**（2021/2022/2025）→ 可选跑池 **17→41**，**能力分母仍 2**；⑥ **已完成推送**——推送前发现远端另有 **3 个文档提交**（本地视图 stale → 实际已分叉），经**合并**（`ad8a17c`）后 fast-forward 推送，远端 `main` 已 = 本地 = `ad8a17c`（`ls-remote` 复核）；⑦ **工程资产移交清单已同步真值源**——初稿（00:21）早于④⑤口径变更，已校正 real_corpus 92→93、runnable_pool 17→41、覆盖率 15.2%→15.1%、presolve `_try_` 53→24、pytest 813→830p/16s、推送状态（详见行动清单 #7）；⑧ **对外文档口径复核（第 3 轮，全仓扫描）**——发现公开文档 `docs/POSTMORTEM.md`（自 09-27 起**无更正声明**，且 §5 自述「引用任何数字前必读」）残留 4 处过期数（题库 92→93 / 覆盖率 15.2%→15.1% / 可选跑池 17→41 / 「唯一那次 LLM 解出 1/2」→ 已作废），已**顶置更正 + 就地刷新**该表；并澄清扩池构成（runnable_pool 41 = 自有 2 + 外部 39，NYU 34 为独立口径）。⑨ **2026-10-08 雷 0（P0-3）二次补修收口**——`ad61c8b` 首修后本文件一度自相矛盾（雷 0 标题已标 ✅，但 TL;DR/体检表/行动清单仍写"未修"）；经回真值源**实跑复核**，发现并非"没修"而是**只改了一半**：更正说明加了、但摘要行仍裸引「LLM 自主推理 1/2」，且口径铁律硬编码「分母是 92」（机器值 93）。已补修 `099011b` + 护栏 `0dc1bcc`，三处状态已对齐（详见雷 0）。
>
> **🔄 2026-10-08 补记（接管轮）**：P0-4 已全部收口（`benchmark_heldout.py` 真跑无 provider → fail-closed 拒绝，`c37efe1`/`d94bca3`）；接管的未提交改造流已落地为「**provider 存活单一真值源**」（新增 `scripts/_llm_pool_status.py` + 护栏 `tests/test_provider_liveness_single_source.py`，提交 `e498be8`/`9458606`，遵第 ⑫ 道拆两笔）——「谁活着」不再手写进注释/默认值，一律查 `logs/llm_probe` 新鲜快照（fail-closed，未知≠可用）。同类假承诺残留（`setup.sh`/`start_race.bat`）一并清除。

---

## 一、人话版 TL;DR

1. **这个仓库现在最大的问题不是"能力不够"，是"对外数字不可信 + 收尾卫生没做完"。** 能力边界已经用多次独立实测钉死了：外部 held-out 池上，大模型**独立解出 0**（17 题池与 41 题池两轮一致）。~~解出的那 9 题 100% 是确定性预扫~~ → **2026-10-08 复核作废：9 中 7 是占位词假命中（ingest 占位真值自证，机制为推断），真解仅 2（dnui/reverse_js）**；当前唯一可信确定性基线 = **41 题池 8 题**（2026-10-09 刷新 +mhk2+ziphard，同日 sha256 仲裁修复后 primes 真解 12.0s 验真补入，证据 `ctf_agent/logs/presolve_resweep_20261009.md`）。这是真实边界，不是调参能救的。
2. ~~**最刺眼的一处**：唯一真值源（`_kpi_canonical.py`）输出被 09-29 实测推翻的旧结论（"大模型自主 1/2"）~~
   ✅ **2026-10-08 二次补修后收口**（详见雷 0）。教训值得单列：**首修只改了「加了更正段落」，没改「数字所在的那一行」**——更正写在下方长段落里，而摘要行仍裸引「LLM 自主推理 1/2」；更隐蔽的是口径铁律行硬编码「分母是 92」（机器值早已 93）。**陈述离开关联上下文就自动退化成虚假声明**——数字都对，摆错位置就是撒谎。补修 `099011b`（注入机器值 + 摘要同行标作废）+ `0dc1bcc`（护栏入 CI，含合成自检）。
3. **次刺眼**：跑批脚本默认 provider 是**已欠费的 baidu**，默认跑**全部题**。按默认一跑就是"死 provider + 全量烧钱"。
4. **还有一颗静默雷**：`git add -A` 会把 **6854 个文件**（其中 6847 个是竞赛遗留的第三方基准仓）灌进仓库。
5. **一句话建议**：先把讲台擦干净（口径 + 默认值 + 门禁脚本，都不花钱），再决定要不要花 ¥1–2 去买 5 题真跑数据，最后再做归档和复盘。

---

## 二、现状体检表

| 项目 | 状态 | 实测说明 |
|---|---|---|
| 分支 / 远端 | 🟢 | 本地 `master` **与远端 `origin/main` 完全同步**（无 ahead/behind）。⚠️ 推送前曾发现远端另有 3 个文档提交（本会话本地视图 stale → 实际分叉），已**合并**（`ad8a17c`，双亲 `b987167`+`9fd8b4d`）后 `9fd8b4d..ad8a17c` fast-forward 推送；**最新一次推送的 sha 见第五节**（此处不钉死 sha，避免每次提交后即过期） |
| 未推送提交归属 | 🟢 | **2026-10-03 逐条核验：22 个提交全部属他人/多会话；已按授权推送**（qr-solver `75b7fa4`、leak-baretoken `420f5ed`、kpi-crossaudit `1cfbc90`/`75bd9be`、gu-envelope `a1407a7`、本会话 `6790751`/`7859665`/`5c70e76`/`66995a6`/`11e3d05` 等）；用户 2026-10-03 明确授权「最后再推」→ **已推送**（远端 = 本地，见第五节） |
| 三池假命中治理 | 🟢 **2026-10-03 已修** | presolve **B 组假命中 11→1**（internal92 6→0 / nyu34 3→0 / cybench13 2→1），**A 组真命中不变**（74/2/2）；残留 1 条＝cybench `data_siege`（pcap 内含貌似合法诱饵 flag，无真值不可辨）。证据 `heldout_evidence/presolve_audit_*_v3_20261003.json` |
| 10733 语料缺口 | 🟢 **2026-10-03 已补齐** | 归档恢复 `race_details/10733.json` + 原始 URL 下载附件 `task.py`（本地 gitignored）+ 新建 `data/questions_real/crypto/10733.json`（id=10733）；`_kpi_leak_crossaudit` 的 `missing_corpus` **1→0**；`real_corpus` **92→93**（`11e3d05`） |
| 工作树 | 🟢 **2026-10-08 接管后完全清零** | 本次会话共 5 笔提交（`e498be8`/`9458606`/`fc4d866`/`991d4fa`/`0d5ad75`）；**`git status` 干净、`git add -An` = 0**。cybench 6847 文件仍由 `.gitignore` 排除 |
| KPI 真值源 | 🟢 **2026-10-08 已收口** | `ad61c8b`（10-01 首修：读 09-29 证据 + 更正说明）→ **10-08 复查发现两处残留**：①摘要行裸引「LLM 自主推理 1/2」无同行作废标记 ②口径铁律硬编码「分母是 92」（机器值 93）。已补修 `099011b` + 护栏 `0dc1bcc` |
| 门禁脚本 | 🟢 **已修** | `test_file_guard.py` 已于提交 `834bffd` 入库（`git ls-files` 可查） |
| 跑批默认值 | 🟢 **已修**（2026-10-08） | `eval/benchmark.py` 默认改 `deepseek`（`d51fdae`）；`benchmark_heldout.py` 真跑无 provider **fail-closed 拒绝**（`c37efe1`/`d94bca3`）。另落地「provider 存活单一真值源」（`e498be8`/`9458606`）：可用性一律查 `logs/llm_probe` 新鲜快照，禁手写 |
| 能力水位 | 🟡 | held-out 大模型自主解出 **0/17**（关早停 + 预算 2.5 倍重测仍 0）；~~解出 9 题全来自 presolve~~ → **2026-10-08 复核：9 中 7 系占位词假命中、真解仅 2（dnui/reverse_js）**；当前唯一可信确定性基线 = **41 池 8 题**（2026-10-09 刷新+仲裁修复，`ctf_agent/logs/presolve_resweep_20261009.md`） |
| 真值判据 | 🟢 **2026-10-08 修复** | `flag_matches` 三形态（明文 / sha256占位 / None+flag_sha256）——旧 gate 漏第三形态 → Google CTF 扩池 **40 题（去重）**判分权被废；`a9e32fd`/`9bb0678` 修复；NYU 34 复核 A=18/B=16 原样复现（该池不受影响） |
| 扩池 | 🟢 | 可选跑池 `heldout_runnable_pool` = **41**（`_kpi_canonical.py` 机器真值）= 自有 **2** + 外部 Google CTF 采源入池 **39**（`data/questions_external/`，2021–2025，40 题经排除链）。另有纽约大学（NYU）采源池 `data/questions_ext/` = **34 题**，属**独立口径**（供 `_envelope_band.py` 分档，A 档=`nyu_static_envelope`），**不并入** runnable_pool。均 gitignore 不入库。**能力分母仍 2，两口径禁混算** |
| 计划文件 | 🟢 | 本文件已重建（原为空且停更于 09-21） |

---

## 三、五颗雷（按危险度排序）

### 雷 0 ✅ 已收口（`ad61c8b` 首修 2026-10-01 → `099011b` 补修 + `0dc1bcc` 护栏，2026-10-08）唯一真值源自己输出过期结论（P0-3）
- **证据**：`_kpi_canonical.py:69` 固定读 `benchmark_report_clean2_20260922_deepseek.json`；`:68` 注释写「LLM 自主推理 1/2：dnui_keyboard」；`:280` / `:349` 输出模板生成「LLM 自主推理 {n}/{pool}」。
- **冲突**：09-29 全 17 题实测推翻该题归因——`real_crypto_dnui_keyboard` 实为 `solved_by=presolve`（tokens=0、dur=78ms），整池 `main_agent_llm`＝**0/17**。
- **严重性**：治理体系建立在"数字只有一个来源"上，而**这个来源输出的是被自己后续实证推翻的旧数**。
- **处置（2026-10-01 首修）**：canonical 的 held-out 结论改为带更正说明——明确宣告该 LLM 自主数不成立、应作废，当前可验证值为 0。终值依据已由下方 🔴 段落的独立复现坐实，**不再需要外部确认**。
- **🔴 2026-10-01 已由新跑批独立复现坐实**（不再是"疑似"）：首批 NYU 5 题试跑在**冷黑板 + E3 ON + deepseek** 下，`real_crypto_dnui_keyboard` **再次**被判 `solved_by=presolve`（78ms、tokens≈0）。即 canonical 那句「LLM 自主推理 1/2」是错的，可放心按"作废"处理。

- **⚠️ 2026-10-08 复查：首修漏了两处残留（现已补修 `099011b`）**
  重申先看结论：**首修改的是「有没有写更正」，漏的是「数字所在的那一行」**。三处具体被发现：

  1. **摘要行裸引作废数字**：`render_md()` 的 held-out 摘要行仍直书「LLM 自主推理 1/2」，
     而更正说明写在下方长段落里。只读摘要、或复制该行（它被设计为「引用者照搬」）
     的人拿到的正是被推翻的数字 —— 这也正是本文件上一版 TL;DR 仍把它判为"未修"的原因。
     → 现改为同行标注「（⚠️ 已作废：该笔归属经复核实为 presolve，当前可验证的 LLM 自主解出数 = 0）」。
  2. **口径铁律硬编码过时分母**：同一输出的「口径铁律」行写死「分母是 **92**」，
     而 `real_corpus` 机器计数早已是 **93**（10-03 补齐 10733 后 92→93）。该行措辞是
     「凡说能力 X% 必须显式声明分母是 ___」，是所有下游被要求照搬的规则 →
     真值源在这里说错，下游连错数字一起继承。
     → 改为注入 f-string 机器值，**而非把 92 改成 93**（让手写从此失去机会）。
  3. 同文件另有 4 处注释手写 92，一并改为「一律取 `canonical_kpi()['real_corpus']`」。

- **护栏 `0dc1bcc`（`tests/test_kpi_canonical_no_hardcoded.py`，8 passed / 0.68s）**：两条不变式 ①口径铁律宣示的分母 == real_corpus 机器值
  ②statement 宣告当前为 0 时摘要引用的历史数必须**同行**标作废。**不锁具体数**（92/93/2 均不写死），
  只锁「两处必须是同一个数」且取自 `canonical_kpi()` 本身 → 随数据集自适应。
  变异验证：M1 分母回退 92 → 1 failed；M2 摘要删标记 → 1 failed；
  **M3 两检测器同时削弱为恒空 → 3 failed，全靠 5 条合成自检抓住**（真数据当前自洽，
  weakening mutation 在真数据上永不可杀 —— 与题库真值完整性护栏 M2 同一教训）。

---

## 二之二、首批 NYU 5 题实测结果（2026-10-01 已执行，已授权）

**预算**：单题 80K / 全局 450K token、只 deepseek、并发 1、墙钟 180s、E3 ON、冷黑板。
**实耗 161,604 token**（约 ¥0.6–1.3，上界 ¥1.3，**未突破 ¥2**，远低于"突然没 3–4 块"的红线）。

| 口径 | 结果 | 说明 |
|---|---|---|
| `main_agent_llm`（大模型主链路） | **0 / 5** | NYU 5 题全 `race_abandon`，耗时 8.3–32.6s，题均实际执行 |
| `presolve`（确定性预扫） | **2 / 2** | `real_crypto_dnui_keyboard` 78ms、`real_reverse_js` 18ms |
| 完整性 | `interpretable=true`、`truncated=0` | 结果可解释、无截断，可判读 |

**抽样方式**：按比例分层 crypto1 / forensics1 / misc1 / rev2（避开预扫可秒解的 `baby_s_third` 与输入有缺陷的 `des2bites`），避免"只挑 crypto 这种最强类别"造成的高估。

**诚实限定**：样本 n=5，远低于样本阶梯（8→12→20→30→60），**0/5 不可表述为"能力 0%"**；本轮单题 80K 低于 ceiling8 的 200K，故本轮本身不足以排除预算因素（真正排除预算的是 09-29 那次 200K×2.5 的重测）。NYU 存在记忆污染，**分数不得对外当能力引用**。

**证据**：`heldout_evidence/benchmark_report_nyu_trial5_20261001_deepseek.json`（已核验与原始报告一致，原有证据未被覆盖）。

---

### 雷 1 ✅ 已修（提交 `834bffd`，2026-10-01）门禁脚本没入库 → 新环境拦死所有提交（P0-2）
- **证据**：`git ls-files --error-unmatch ctf_agent/scripts/test_file_guard.py` 报错（未跟踪）；`pre-commit:172` = `"$PY" scripts/test_file_guard.py --staged || exit 1`（`PY` 定义在 `:29`，回退 `python`）。
- **后果**：新克隆/换机器 → 脚本不存在 → python 找不到文件即非零 → 触发 `exit 1` → **所有提交被拦死**。
- ⚠️ **自指陷阱**：`test_file_guard.py:21` 的 `TEST_PATTERNS` 含 `(^|/)test_[^/]+\.py$`，**正好命中它自己** → 它被判为"测试文件"。若与任何实现文件（如修 KPI 脚本）同提，会被第 ⑫ 道判「测试+实现混提」拦死。
- **处置**：**单独成一个提交**入库；或加白名单/改名（改名需同步改 `pre-commit:172`）。
- **✅ 2026-10-01 已修复**：提交 `834bffd`（只含该脚本一个文件，符合第 ⑫ 道）。`git ls-files` 已可查到；全闸门绿（⑥ 快速回归 152 passed、⑦ 文档一致性、⑩ 反注水、⑪ 结构、⑫ 测试文件守卫）。**新克隆拦死提交的隐患已解除。**

### 雷 1.5 ✅ 已收口（`d51fdae` 2026-10-01 + `c37efe1`/`d94bca3` 2026-10-08）跑批默认值 =「死 provider ＋ 全量烧钱」（P0-4）
- **证据**：`eval/benchmark.py:340` 与 `scripts/benchmark_heldout.py:486` 的 `--provider` 默认均 **`baidu`**（MEMORY ④：欠费 `403 account_overdue`）；`benchmark_heldout.py:489` 的 `--limit` 默认 **`0`＝全部**；`:31/:33` 文档串仍教 `--provider baidu`、`真跑需要 baidu 凭证可达`（已过期）。
- **冲突**：违反跑批铁律「真跑一律 deepseek、先跑 ≤5 题、先估成本报授权」。
- **处置**：付费试跑**之前**补 fail-closed 安全前置——默认值改 deepseek（或取消默认、强制显式指定）、`limit` 默认 5、更新过期文档串。**这是 5 题试跑的前置条件。**
- **🟡 2026-10-01 部分修复**：
  - ✅ `eval/benchmark.py:340` 默认已由 `baidu` 改为 `deepseek`，帮助文本同步注明 baidu 欠费不可用（提交 `d51fdae`）。未改其 `--limit` 默认（mock 回归依赖跑全量）。
  - ✅ **2026-10-08 已由原会话补齐 `scripts/benchmark_heldout.py`**（`c37efe1` 实现 + `d94bca3` 测试）：`--provider` 默认取 `CTF_AGENT_LLM_PROVIDER`；`--run`（非 mock）无 provider → **RC=2 且在选题之前拒绝**（零副作用）；真跑前强制打印规模+provider。工作树当前无其未提交改动，本条全部收口。

### 雷 2 ✅ 已非破坏性收口（提交 `596b056`，2026-10-01）6847 个竞赛遗留文件会被误提交（P0-1）
- **证据**：`git add -An` = 6854 个文件，其中 **6847 个在 `2027-prep/cybench/`**（vendored 第三方基准仓：Dockerfile / LICENSE 11KB / grade_benchmark.py / run_benchmark.py …）。
- **已正确忽略**（不会误加）：`_archive`（6945 文件）、`_tools_ghidra`、`data/questions_ext`、`ctf_agent/data/questions_external`、`logs`。
- **未被忽略**：`2027-prep`、`ctf_agent/scripts/test_file_guard.py`、`ctf_agent/heldout_evidence`、`deliverables`（后者本就入库）。
- **已跟踪的竞赛遗留共 4 份**：顶层 `2027-prep/差异分析-SOTA对比-20260928.md`；`ctf_agent/2027-prep/` 下 3 份（`M1_分辨率_20260929.md`、`M2_E3对照_20260929.md`、`作战规划_2027.md`，均来自提交 `51643ed`）。
- ⚠️ **归档陷阱**：`M2_E3对照_20260929.md` 是 MEMORY 中 **E3 定调的引用源**（"生产默认 OFF、评测强制 ON"），有持续价值，**不能随目录整体归档**——应先迁到中性目录（如 `docs/`）再归档其余。
- **处置**：用户明令不得擅删 → 二选一：① 加 `.gitignore`；② 归档到 `_archive/2027-prep-legacy/`（M2 先迁出）。**需你拍板。**

### 雷 3 🟢 未推送提交已获授权推送（2026-10-03：6→22）
- 见体检表。2026-10-03 已逐条核验，22 条**全部属他人/多会话**。用户当日**显式授权「最后再推」**（豁免 10-01「不推送」）→ 本轮按该授权执行推送（推送前发现远端另 3 个文档提交 → **合并** `ad8a17c` 后经 SSH fast-forward，**未 `--force`**；`ls-remote` 复核远端 = `ad8a17c`）。⚠️ 工作树另有 3 处**他人在途**改动（`git_hooks/pre-commit`、`benchmark_heldout.py`、`test_kpi_canonical.py`）**未提交、未推送**，仍守并发红线。

---

## 三之二、能力层两条扩能路径的探查结论（2026-10-03，零成本、未花钱）

> 用户授权「都可以」后，在**不花钱**前提下探查了「扩能力」的两条路，结论如下，供后续会话不再重复投入。

### B 层：从 NYU / Cybench 池扩确定性求解器 —— 🟡 池已盘点，无低成本增量
- **池现状**：NYU 34 题（干净 33，presolve 命中 2/34→干净 1/33）、Cybench 13 题（presolve 命中 2/13）。
- **探查**：逐题枚举剩余题型（crypto 复钥 / reverse / pwn / forensics）。尝试 `another_xor`（重复密钥 XOR）——已解出密钥前 5 字节 `A qua`，但全钥 L=25 因明文含空格、flag inner 不可破，登山法不收敛，**主动放弃**（避免无限投入）。
- **结论**：剩余可预扫题**绝大多数需要真实 crypto/reverse/pwn 工作**，非"加个字符串规则"能拿下。唯一能真提解出率的方向＝**补真实能力**（写求解器），不是加预算（预算非瓶颈已由 09-29 2.5× 重测证否）。

### C 层：扩「真实输入池」——✅ 2026-10-03 已引入新源（Google CTF）
- **机制**：`scripts/select_candidates()` 排除链＝训练污染 ∪ writeup 重建 ∪ 自撰 ∪ 已泄漏 ∪ 无 sha256 → 内部 92 池里仅 **2** 题满足"干净真值 + 真实输入"（**能力分母**）。
- **已执行（用户授权「可以引入」）**：从 `google/google-ctf` 采 2021/2022/2025（crypto/rev/misc）→ `fetch_google_ctf.py` + `ingest_external_ctf.py` 落 **25 题**（三红线：只存 sha256 / brief 取自官方 description / 附件字节级不含真 flag）→ **可选跑池 17→41**（`heldout_runnable_pool`）。
- **口径不变（重要）**：外部采源进入**可选跑池**，**能力分母 `heldout_candidates` 仍 = 2**（治理红线：两口径禁互换/合并/造比率）。若要**扩能力分母**须重新定义口径 —— **未做，需你拍板**。
- 🔧 **环境坑（复用）**：`git/trees?recursive=1` 大响应（~14 MB）在本机被截断（`IncompleteRead`）→ 改经 `gh api` 落本地 tree 快照驱动抓取；临时 driver 与 staging 均放 gitignored `data/results/` 并在 ingest 后删除（staging 含明文 flag）。

### 三之三、AICTF 备战启动：P0 立度量 + P1 首轮（2026-10-03 晚，用户拍板「可以」）

**定位变更（用户 2026-10-03 晚）**：推翻「非竞赛工程/能力项目」定位 → **目标＝自主智能体 CTF（造 Agent 自动解经典 CTF）取得好名次**。规划可花钱但**预算 ≤¥2、分步汇报**。赛道经确认＝自主智能体（非 AI 安全主题、非 AI 辅助）。

**情报与路线图**：见 `deliverables/规划手册/AICTF自主智能体CTF格局与备战路线图-20261003.md`（六章 + 114 真实来源，零花费产出）。最近窗口＝**2026Q4 安恒「AI Agent CTF」随第九届西湖论剑回归**（赛制已公布、日期待官方）。

**P0 度量冻结（¥0，本轮生效）**：
- 进度唯一分母＝**held-out 可选跑池 41**（每批报告必须声明子集分母 `n/41`）；NYU 200 / Cybench 40 仅作对照回归。
- 主链自主解出基线＝**0**（09-29 全池 + 10-01 NYU 5 题两次独立实测）。
- 「presolve 14/93=15.1%」一律表述为**确定性命中覆盖率，非能力**；验收禁「能力 X%」无分母表述。
- 静态榜单系统性高估（CTFusion：静态 14.4% vs Live 6.3%）→ 一切验收以 held-out 对抗污染口径为准。

**P1 首轮（✅ 已执行 2026-10-03 19:18–19:21，实耗 172,747 tokens ≈¥0.3–0.9，预算内）**：41 池前 5 题（1 crypto + 4 misc，全 GCTF2021）× deepseek 主链路；冷黑板 + E3 ON + require_sha256；硬封顶 80K/题、40 万全局（未触顶）。**结果＝0/5（自主解出仍 0）**，`integrity.interpretable=true`、`zero_work_not_attempted=0`、5 题**全部 `race_abandon`（预算反思早停，非基础设施故障）**；轨迹显示 agent 仅做 ~8 步 recon 即自我放弃（`goal_log.jsonl` 实录 `recon:command ×2-3, steps=8`）。**诊断**：瓶颈不在预算（token 远未顶格）而在**反思环过早 ABANDON**——即路线图 P2「分层规划 + 工具化 + RAG 抗幻觉 + 记忆」四件套针对的病灶；下一步候选＝P2 落地（零成本）或再跑 5 题扩样（≈¥1，须单独授权）。证据：`data/results/heldout/G_rerun_20261003_191824/`（时间戳目录，未覆盖旧证据）。

**P2 首刀 + P1 第二轮（✅ 用户 10-03 晚拍板「12」＝P2 治过早放弃 + P1 扩样都做）**：

- **P2 首刀（¥0，提交 `09ee5fb` 实现 + `78bec78` 测试）**：反思规则⑥加 **token 口径**——`BudgetState.token_ratio`（None=未知→旧行为，向后兼容），token 已知时须 **token 也 ≥60%** 才允许 ABANDON；`MainAgent` 新增 `token_usage_fn` 注入点，`run.build_solver` 把真实 token 记账（`_usage_cv` 盒 + BudgetTracker）除以单题预算注入。止损语义保留（token 烧穿场景不受影响）。变异验证：注释守卫→2 新用例 FAIL→恢复；全量 **835 passed / 16 skipped**。
- **P1 第二轮（✅ 19:54–20:00，实耗 387,783 tokens，累计两轮 ≈¥1.0–2.0——预算基本用尽，后续跑批须重新授权）**：41 池第 6–10 题（GCTF2021 tiramisu/tonality + GCTF2022 custom-protocol/cycling/electric-mayhem-cls）× deepseek，口径同首轮（冷黑板 + E3 ON + require_sha256）。**结果＝0/5**（`by_error`: race_abandon ×4 + budget_exceeded ×1；`interpretable=true`）。
- **修复被证实生效（A/B 对照）**：首轮每题 token 仅 ~35%（34.5K/80K）就被步数规则掐死；第二轮每题烧到 **84–104%（67K–83K）** 才停——不再有「token 还剩大半就认输」。0/5 是**能力事实**（这批 2022 题更难），不是机制截断。
- 累计 held-out 对抗口径：外部池 **0/10**（本会话两轮）。**预算结论不变**：钱已花到位，瓶颈=自主推理能力本身 → 下一步只有 P2 四件套剩余部分（分层规划/记忆/RAG）是合法路径，扩样/加钱已无增量。

**P2 第二刀：题内跨步「已试策略黑板」（✅ 2026-10-03 晚，¥0）**：

- **病灶**：plan prompt 只含「近 3 步摘要」（`steps[-3:]` 窗口），更早试过的失败策略被挤出窗口 → 规划器反复重提同款失败路径（P1 轨迹实录 `recon:command ×2-3` 空转），预算烧在重复上。
- **修法**（纯规则零 LLM，与 E6 few-shot / E3 证据注入同一 A/B 模式）：新模块 `core/strategy_blackboard.py`——每步「策略签名（stage|action|tool）+ 结局（失败/无产出/有进展）」结构化沉淀；`AgentContext.record()` 同步喂黑板；`build_plan_prompt` 注入【已试策略黑板】块（含各签名失败次数、最近错误/观察、近 5 步重复率 ≥40% 换策略告警），让规划器显式避开已失败路径。签名条目 LRU 上限 32 防 prompt 膨胀；黑板故障一律静默退化（不阻塞主流程）。
- **边界澄清**：本题内记忆（每次 `solve()` 新建），与跨会话 flag 缓存黑板 `data/results/blackboard.json`（presolve）互不相干；不改任何反思决策规则——行为改变仅经 prompt 注入达成。
- **验证**：新增 15 例回归（聚合/签名区分/repeat_ratio/summary 告警/LRU 淘汰/脏步不抛/AgentContext 接线/prompt A/B 逐字等价/6 步窗口挤出核心价值用例）；**变异验证**：注释 prompt 注入守卫 → 2 例 FAIL → 恢复复绿；全量 **850 passed / 16 skipped**（基线 835+15）。
- **待 A/B**：下次获授权真跑时对比黑板注入前后的重复签名率与解出率（黑板不烧钱，随跑批顺带产出 `metrics` 指标）。

**P2 第三刀：卡壳「分层作战视图」（✅ 2026-10-03 晚，¥0）**：

- **病灶**：flat Plan-Act-Observe 每步只看「上一步 + 近 3 步摘要」，无全局路径视图 → 空转。已有题型标准流程（`TemplateBank.standard_flow`）是静态全文注入 system，与「已试失败路径」不联动——模型看到长清单却不知哪条已死、哪条没试。
- **修法**（纯规则零 LLM，延续黑板/E6/E3 A/B 模式）：新模块 `core/hierarchical_plan.py`——把「题型标准流程（候选路径）」与「黑板失败签名（`failed_signatures()`）」桥接成【分层作战视图·卡壳换路】块：路径序号 + 已试失败签名 + 决策规则（跳过已试、优先未试、重试须实质不同）。**仅当黑板启用且已有失败/无产出签名时注入**（真正卡壳换路时点），首步/顺利推进时 prompt 不变。
- **顺带修正黑板语义**：`summary()` 原只判「entries 非空」即注入 → 纯 progress 路径也被标「勿重复」（语义错且破坏 A/B 等价）；改为**无失败/无产出时不注入**。
- **验证**：新增 8 例回归（黑板 None/无失败→空串；有失败→含路径+签名+决策规则；无 flow 题型仍出签名+规则；`failed_signatures` 排除纯 progress；prompt 集成 + 等价性）；**变异验证**：注释分层视图守卫 → 注入用例 FAIL → 恢复复绿；全量 **858 passed / 16 skipped**（835 基线 + 15 黑板 + 8 分层）。
- **待 A/B**：同黑板——下次授权真跑对比分层视图注入前后重复路径率与解出率。

**P2 第四刀：RAG 语料审计 + A/B 验证跑批（✅ 2026-10-03 深夜，用户「都可以」授权）**：

- **RAG 语料审计（¥0，提交 `816fa5e`+`27b9f39`）**：新脚本 `scripts/_rag_corpus_audit.py`——①泄漏红线：语料 22 条 × 两外部池 74 题三层比对（题名/描述特征 token≥60% 覆盖/flag 值）**零交集**，RAG 开启无评测污染风险；②台账对齐：offline_verified 14 题 vs 语料 verified 10 条（gap 4 条只报告不编造）。回归 6 例。
- **A/B 验证跑批（≈¥0.6，实耗 3m48s）**：41 池第 11-15 题（GCTF2022/2023 crypto×5：pqc/enigma/maybe-someday/cursved/least-common-genominator），P2 三刀默认生效 + 规则⑥闸门 ON + 冷黑板 + E3 ON + 硬封顶 80K/题·40 万全局。**结果＝0/5**（race_abandon×4 + budget_exceeded×1）。证据：`data/results/heldout/G_p2ab_20261003_221727/`（时间戳目录，未覆盖旧证据）。
- **止损语义确认正确（非回归）**：每题 race_abandon 发生在两轮 attempt 合计 token ≥60% 且零候选时——P1 首轮「token 仅 35% 就认输」未复发；budget_exceeded 题 83.6K/80K 触发步级硬停，口径精确。
- **新发现（下一刀目标）**：E2「连续同动作 3 次→强制切换」只看 action 名不看实质——本轮 **47% 的步被强制切换**（前两轮 17-24%），crypto 题 LLM 连续写**不同算法**的解密脚本是正常探索，却被 E2 每 3 步误伤打断（strategy_switches 空转、advisor_hint 反复覆盖）。修法候选：E2 改用与「同参数重复检测」一致的三元组签名（action+observation[:200]+tool）——observation 实质不同（换算法/参数）不算重复。P2 三刀无回归、行为未恶化。

**P2 收尾刀：E2 三元组签名修复（✅ 2026-10-03 深夜，用户「可以」授权，¥0）**：

- **改动**（`core/main_agent.py` E2 块）：判重签名由 `action` 单元组改为三元组 `(action, observation[:200], tool_used)`——与下方「同参数重复检测」对齐：observation 实质不同（换算法/参数/输出）的正常探索不再被强切；真死循环（同动作+同输出前缀+同工具）仍被拦截。advisor_hint 与日志文案同步更新。
- **验证**：新增 2 例回归（①同 action 不同 observation 的 crypto 探索 12 步内 switches==0；②同前缀 200 字符尾部不同的近似重复仍触发强切）；**双重变异验证**（签名退化回 action-only → 探索用例红；整体禁用 E2 → 前缀用例红）；全量 **866p/16s**。
- **测试坑（变异前自查揪出）**：probe 的 plan 工厂写成了同步函数 → `await plan_step` 报 "object dict can't be used in await" → 每步走异常分支，探索用例「假绿」（switches==0 是因为 action 从未生效）。plan/act mock 必须 async；判「假绿」看测试日志有无 plan 步异常 WARNING。
- **跑批口径提醒**：日志统计脚本若 grep「强制切换策略」旧文案会失配，新文案为「连续同策略签名3次检测」。下一轮 A/B 对比基线以此为准。

**P2 全链验证跑批 G_p2c + E2 去重修复（✅ 2026-10-03 深夜，用户「可以」授权跑批，¥0 修复）**：

- **跑批（≈¥0.5-0.6，实耗 2m50s）**：41 池第 16-20 题（GCTF2023 mhk2/primes/zip + GCTF2024 blinders/desfunctional，crypto×5），与 G_p2ab 完全同口径（同 provider / 冷黑板 / E3 ON / 规则⑥ ON / 80K·40 万封顶），**唯一变量＝E2 三元组签名修复**。**0/5**（budget_exceeded×2 + race_abandon×3）。证据：`data/results/heldout/G_rerun_20261003_232435/`（时间戳目录，未覆盖旧证据）。
- **强切率 35%（33/94 步）vs 基线 47%**——降了但**未消失**：逐条日志显示 mhk2 从第 4 步起**每步**都触发强切。
- **🔴 深一层根因**：`observe_step` 对 `kind="script"` 且 output 为空时写 `observation=""` → 三元组恒等 `("script","",None)` → E2 每步命中；而 E2 命中后 `continue`，**把下方「同参数重复检测 → presolve 兜底 → 止损 break」整条硬止损路径屏蔽**——这正是 2 题烧穿到 budget_exceeded 的机制。空观察不构成「产出重复」的证据。
- **修法**：`AgentContext.e2_switched_signatures`（已强切签名集合）——**同一签名只强切一次**，重复则放行给硬止损，恢复「软 switch 优先于硬放弃」的互补语义（此前是互斥：软切换吃掉硬止损）。
- **验证**：新增 2 例回归（空观察恒等流转 switches==1 且 <12 步即止损 / 不同签名互不影响）；**变异验证**（去掉去重守卫 → 2 例红）；全量 **868p/16s**。两例旧断言同步校正：原 `llm_calls==12`（＝「烧满预算」）在新语义下不成立（硬止损提前 break）→ 改为「≤12 上限」+ 差异化观察场景另测真封顶；归因由 unresolved 放宽为 unresolved/stuck_loop（后者才是「无报错+零候选」空转的正确分类）。
- **待验证**：去重修复的真实 A/B 效果——建议下一轮授权跑批时**重跑已跑过的 16-20 题做配对比较**（同题前后对比，比跨题对比更能隔离变量）。
- **⚠️ 事实纠正（实测重算发现）**：此前口头表述「crypto 已连跑 15 题」**不准确**——P1 首轮 5 题是 **misc×4 + crypto×1**（abc-arm-and-amd / david-and-the-tree / filestore / ican-tbelieveit-snotcrypto / h1），即 **misc 题型首轮就已实测且同样 0 解出**，「换个题型试试」的前提不成立。
- **四轮真跑汇总（从日志+报告实测重算，非复述）**：累计 **0/20**，总步数 346，合计 **1,278,637 token**；强切占步比 24%→17%→47%→35%。
- **收口交付物**：`deliverables/规划手册/P2架构治理复盘与四轮真跑证据汇总-20261004.md`（人话版结论 + 五刀清单 + 口径警示 + 术语对照；交付物目录不入库，无需过门禁）。
- **能力缺口实测清单（¥0，10-04 凌晨）**：`deliverables/规划手册/能力缺口清单-20题实测-20261004.md`——从 goal_log 轨迹 + 题面附件倒推，**「0/20」拆成四类**：工具链缺口≈5（SageMath/格基/侧信道/跨架构二进制，含 2 题需靶机）/ 需靶机≈6（离线结构性不可解）/ 纯推理≈8（纯 Python 源码审计，理论可解）/ 离线可补算法≈3（Enigma/PKZIP/LCG）。本地依赖实测：sympy/gmpy2/Crypto/numpy ✅，scipy/fpylll/SageMath ❌。
- 🔴 **口径升级结论**：①「0/20」混合了三种性质不同的失败，对外引用会失真 → 应分「离线可做集（≈11 题，真实推理分母）/ 需靶机集 / 工具链依赖集」三口径统计；② **agent 自评不可信**——20 题末次自评 18 题写「无明显能力缺口」，而题面显示真实情况是缺工具/缺靶机，能力测量不能依赖自我报告。
- **下一步优先级建议**：**B1 补工具链 > B2 提推理**（B1 是确定性工程量、换来确定性可解题量；且 B1 做完后才能干净测量 B2 的真实水位，否则工具链缺口污染推理能力测量）。
- **🔥 B1 第一小步已落地（10-04 凌晨，¥0）**：mhk2（Google CTF 2023，Murakami 背包）用 **python-flint LLL** 做等价密钥恢复，**解出真实题 flag**（sha256 与题面真值 `57fadd46…` 完全匹配）——这是 20 题真跑里**首道被确定性求解器攻破**的题。已工程化为 `core/lattice.py`（LLL+饱和核）+ `skills/crypto_knapsack_mhk.py/json`，提交 `7012221`（实现）/ `448b7cc`（测试）已推送远端。⚠️ **诚实定位**：这是「工具链补齐」产物，**不等于 agent 自主能力**；要让它真正提升能力，须让 presolve 阶段**实际调用**该 skill（接主链待做）。
- **🔥 B1 第二道已落地（10-04 凌晨，¥0）**：`primes`（Google CTF 2023，子集积 mod q）用 **Coppersmith 平滑因子法**解出，**flag sha256 = 题库 `flag_sha256`（`df18e59d…`）完全匹配**。工程化为 `core/coppersmith.py` + `skills/crypto_primes_subset.py/json`，提交 `c501266`（实现）/ `6d1ae1d`（测试），**未推送**（红线⑥需豁免）。
  - 三条硬坑（已固化进模块文档头）：① 格多项式**必须首一** `f=y+c`，非首一时的可达 X 上限从 2^1419 塌到 2^391，真 y=2^1446 永不命中；② **X 必须大于真 y**（症状＝范数低于阈值、基多项式全被 T^m 整除、却无整数根）——注意 chal.sage 里的 `m` 是诱饵，真 (q,x) 是注释值；③ 求根走**精确 Hensel**（`ground_roots` 在巨系数上挂死 17 分钟、`nroots` 不收敛）。
  - 余下工具链题：`electric-mayhem×2` 附件是 21–27 字节的**空 tgz**（power traces 根本没提供）→ 侧信道离线结构性不可做，**降级回「需靶机」类**；跨架构 `abc-arm-and-amd` 待查。
  - ✅ **primes 已接入 presolve 主链（10-04，`087610f` 实现 / `c008acc` 测试）**：`_try_crypto_primes` 从题面/附件抠 (q, x, r)，再用 **`_recover_primes_n` 由 q 反解 n**（`q=next_prime(∏p_{n-r..n-1})` 由 (n,r) 唯一决定 → 滑窗 + 间隙过滤 + nextprime 自校验；0.8s 得 518，假 q 返回 None）。真实题目对象端到端 24.6s 解出、sha256 与题库真值匹配。这是 **B1 首个真正进主链的产物**。
  - ✅ **mhk2 也已接入 presolve（10-04，`c3677d7` 实现 / `6d11f26` 测试）**：`_mhk2_extract` 从 `output.txt` 认出 `a1/a2`（256 个大整数）+ 335 组 `(c1,c2)` 密文，门槛 n≥64（n<48 攻击本就不成立，拒绝而非白跑），`_try_knapsack_mhk` 600s 墙钟、实测 **146.6s 解出**，sha256 与题库真值匹配。
  - ✅ **至此 B1 已破 2 道（mhk2、primes）全部接入主链**，KNOWN_GAP 两个条目均已摘除；接线状态由新增的 `tests/test_presolve_b1_wiring.py` 盯守（未接线＝只是库、不算能力）。
  - ✅ **B1 第三道 cycling 已落地并接入主链（2026-10-05）**：`cycling`（Google CTF 2022，RSA cycling attack）用 RSA 循环攻击解出，flag = `CTF{Recycling_Is_Great}`（sha256 前缀 `acbe3fce`＝题库真值），真题端到端 44.97s 解出、自带加密回验通过；工程化为 `skills/crypto_cycling.py/json`，由 `_try_cycling` 接入 presolve（`_WIRED_SKILL_MODULES` + 任务列表）。提交 `7f17ec1`（实现，含 README 中英 skill 计数 59→60）+ `e9842ef`（测试），**已推送远端**，拆分两次提交过门禁⑫。
  - ✅ **B1 第四道 electric-mayhem-cls 已落地并接入主链（2026-10-05）**：`electric-mayhem-cls`（Google CTF 2022，AES-128 功耗分析 CPA 侧信道）用 numpy 相关功耗分析（HW(Sbox[pt^key]) 逐字节 256 候选 Pearson 相关）解出，flag = `CTF{W0ckAwocKaWoCka1}`（sha256 = `408e722c…`＝题库真值），真题 50 条模拟轨迹（1806 样本/条）端到端解出；工程化为 `skills/crypto_electric_mayhem_cls.py/json`，由 `_try_electric_mayhem_cls` 接入 presolve（提交 + 推送，拆分实现/测试两次提交，过门禁⑫）。
    - 🔴 **纠正旧判**：此前「electric-mayhem×2 皆空 tgz→需靶机」不准确——实证复核（2026-10-05）：**cls 三方数据齐全**（elmo.tgz 118KB 真迹 / firmware.tgz 49KB 真 firmware / stm32f0_aes.json.gz 788KB 含 1806 样本模拟轨迹）＝**纯模拟轨迹离线可解**，无需靶机；**pqc** 的 `firmware.tgz`(25B)/`stm32f0_kyber512.json.gz`(27B) 才是占位符文本（`../challenge/...`），缺 firmware+model → 结构性残缺、离线不可做；**abc-arm-and-amd** 为跨架构 shellcode（chal-aarch64/chal-x86-64 + libc），可构造 payload 但本机无 qemu/WSL **不可执行验证** → 按诚实口径「未运行验证、不算解出」。
  - ⚠️ **KPI 未变**：四题均属 `questions_external`（外部池口径），**不进 `offline_verified=14` 台账**；且属工具链补齐，不代表 LLM 自主推理能力。
  - ✅ **B1 第五道 least-common-genominator 已落地并接入主链（2026-10-05）**：`least-common-genominator`（Google CTF 2023，LCG 参数恢复 → RSA 私钥重建）用纯数论从 `dump.txt` 的 6 个连续 LCG 输出恢复 `(m,c,n)`（令 `y_i=x_{i+1}-x_i`，`n=gcd(y_1²−y_2·y_0, …)`，`m=y_1·y_0⁻¹ mod n`，`c=(x_1−m·x_0) mod n`，自带重放自校验），重放序列按序收集前 8 个 512-bit 质数 → 分解 N → 解密，flag = `CTF{C0nGr@tz_RiV35t_5h4MiR_nD_Ad13MaN_W0ulD_b_h@pPy}`（sha256 = `69981daf9abd…`＝题库真值，且重建 N == PEM.N 自校验通过）；工程化为 `skills/crypto_lcg_recover.py/json`，由 `_try_lcg_recover` 接入 presolve（`_WIRED_SKILL_MODULES` + 任务列表，触发签名＝附件目录同存 `dump.txt`+`public.pem`+`flag.txt` 三件套）。⚠️ 属外部池口径，不进台账，不代表 LLM 自主能力。
  - 🔴 **附件完整性重核（2026-10-05，与上文 ⑬ 旧判冲突，以此为准）**：`scripts/_attachment_integrity_audit.py` 实测外部池 **38/40 题附件已是真实文件**，仅 `electric-mayhem-pqc`（firmware.tgz 25B + stm32f0_kyber512.json.gz 27B 占位符）与 `ican-tbelieveit-snotcrypto`（chal.py 20B 占位符）2 道仍残缺——即此前「外部池 21/40 题附件是符号链接占位文本」**已被「跟随软链重抓」修复推翻**。⇒ 文档 §1 的「纯推理 8 题（单文件 chal.py）」与「离线可补算法 3 题（enigma/zip/lcg）」本机现有真实数据，B2 可测分母应据此重算，不得再沿用「12 道空输入」。
  - ✅ **B1 第六道 ziphard 已攻破并接入主链（2026-10-09）**：`ext_gctf2023_zip`（Google CTF 2023「ZIP」hard 变体）用 bkcrack 已知明文攻击（9 字节明文：BOM+`CTF{` 7 连续 + bkcrack 隐含 CRC 字节 + `}`@49，junk.dat CRC32 逆推作 second-file 交叉过滤）恢复密钥 `7796d1ea 96defd9f d7043705`（=官方 solution README 逐字一致），解密得 `CTF{y0u_u5ed_3xtr@_pl@1nt3xt_t0_d3t3rm1n3_k3ys}`，sha256=`d3109ddee2…`=题库真值 ✓。hard.zip 与官方原版 sha256 逐字同（`bd7584ab…`）。全程 38m33s（MSVC 静态构建，免 Docker/免 vmmem）。**三层 bug 剥洋葱**：① 入库的 1.6.1 适配 patch 把 second-file 检查放 rewind 前→真候选全灭（已修 `53acadc`+守卫 `cb0a97e`，8 例+变异击杀）；② 合成构建器相对偏移/comp-size 自伤（DBG 插桩抓出）；③ 合成实验覆盖真 `second_ciphertext`（CRC 恰同）毒化第二次真跑——铁律：**合成产物绝不与真工件同目录；每轮攻击前用已知真值做 filter 门禁**。接线：`skills/crypto_zip_bkcrack`+`_try_zip_bkcrack`（触发=ext_gctf2023_zip 或描述含 PKZIP；`1355ab9` 入库+候选表补路径），wiring 套件 **24 passed 含 slow e2e**（presolve 触发→solve→攻击→sha256 全链路）。⚠️ 外部池口径，不进台账，不代表 LLM 自主能力。证据：`logs/ziphard_attack_20261009/`。
  - ✅ **41 池确定性基线刷新（2026-10-09，¥0，28m09s）**：`presolve_resweep_20261009` 全池重测（方法论与 10-08 基线逐字一致）→ **TRUE 7/41**（real 2/2 + ext 5/39）：5 题原基线 + mhk2（76.7s）+ zip（1561s，经 presolve 主链路 `WALLCLOCK_ZIPHARD=3600` 正常命中）。🔴→✅ **primes 假命中遮蔽已修（同日）**：根因=chal.sage:31 内置诱饵 flag 经 flag_scan 0.4s 抢跑（as_completed 先到先得）；修=presolve 主入口 sha256 仲裁（`3987beb`：验真候选压过先到未验真者，无真值行为不变；回归锁 4 例 M1M2 双杀）。修复后 primes 走生产入口 12.0s 真解验真 ✓。证据 `ctf_agent/logs/presolve_resweep_20261009.md`。
  - 🔧 **🔴 重大根因修复：presolve flag_pattern 闸误杀 B1 真解（2026-10-05，提交 `76d0450` 实现 + `9fa15aa` 测试，已推送）**：外部题池 **38/40 题** `flag_pattern` 沿用默认 `flag\{[^}]+\}`，而 google-ctf 真 flag 实为 `CTF{...}` → presolve **三处格式闸**（主入口 `presolve()` / `_try_flag_scan` / 黑板缓存）在 `_passes_answer_check` 之前把经 sha256 可证的真 flag 当诱饵丢弃，导致 cycling/cls/lcg **解得对却主链白干**。修复＝新增 `_matches_expected_sha256()`，题面声明 `flag_sha256` 且候选哈希相符时旁路格式闸（sha256 抗碰撞，命中即真值；无真值/不符则行为完全不变，fail-closed）。测试补「主入口端到端」用例（历史假绿根源：只调 `_try_*` 绕过主入口闸）；**变异验证双向通过**。**同源修复（提交 `dd644a1` 实现 / `6742c55` 测试，已推送）**：`core/phases.py` 主 agent 路径亦用 `flag_pattern` **定位**候选，新增 `_broad_sha256_flag()`——声明 pattern 未匹配且本题带 `flag_sha256` 时退回「宽 pattern 扫描 + sha256 仲裁」（严格加法，无真值/无命中即 None，行为不变），堵住 LLM 路径同类隐患。**KPI 未变**（外部池口径，不入台账）。

### 三之三补、B2 能力测量试点（2026-10-05，≈¥0.46）—— **0/5**

- **题集**：外部公开池**全新批次 21–25**（`idea`/`mceliece`/`otp`/`zkpok`/`filtermaze`，全 crypto；四轮已覆盖 1–20，本批**首次真跑**；均**非 presolve 可解** → 可视为 LLM 自主水位）。
- **结果＝0/5**，`interpretable=True`（`attempted=5` / `zero_work=0` / `mechanism_terminated=5`，**零基础设施掐断**）；`by_error`: **race_abandon×2 + budget_exceeded×3**。
- **token**：global **380,676**（idea 52,587 / mceliece 80,147 / otp 86,558 / zkpok 81,331 / filtermaze 80,053）；耗时 2m55s；**4/5 烧到 80K 单题硬顶** → 复现「**钱/预算非瓶颈，架构/能力才是**」。
- **累计**：外部公开池自主真跑 **0/25**（四轮 0/20 + 本批 0/5）。
- **证据**：`data/results/heldout/G_p2b2_20261005_151800/`（gitignored）；配置 `deepseek` + 冷黑板 + `E3=ON` + 预算反思 ON + 硬顶 `GLOBAL=400000`/`PER_Q=80000`。
- 🔴 **踩坑**：父进程残留 `CTF_AGENT_LLM_BASE_URL`（DASCTF 网关）会被 `config.from_env` 采用，但 `print_effective_config_snapshot` 显示 provider 默认端点（**具欺骗性**）→ 真跑前必 `env.pop` 清除（已固化进启动器 `data/results/_b2pilot_launch.py`）。
- **KPI 未变**（外部池口径，不入台账）。

### 三之三补二、架构根因修复：策略签名「空输出塌缩」（2026-10-05，¥0 改造）

- **病灶（从 B2 证据 `data/results/_b2pilot_real.log` 逐行定位）**：**5/5 题在步骤 3–5 即被同一链路弃题**——「连续同策略签名3次检测：强制切换策略 (action=script)」→ 下一步「同参数重复（script）——判定死循环，止损换题」。
- **根因**：`execute_script` 只把 **stdout** 作 observation；脚本报错（traceback 进 stderr）或静默计算 → `observation=""`，且 script/command 步 `tool_used=""`（恒空）→ E2 强切 与 同参数重复检测 **共用** 的三元组签名 `(action, observation[:200], tool_used)` **塌缩为常量** `("script","","")`。于是 **LLM 连续写不同算法的解密脚本（正常探索）被误判「同策略空转」**：E2 强切一次（dedup）→ 下一步命中死循环检测 → `break`。**每 attempt 只活约 5 步**（真正的求救信号被当成死循环掐断）。
- **修法（严格加法，零行为回退）**：`StepRecord` 新增 `plan_fp`（plan 全字段稳定哈希，`json.dumps(sort_keys=True)`+sha256[:12]）；`_strategy_signature` 在观察**无有效载荷**（空 / 仅 `[rc=0]` 前缀）时用 `plan_fp` 参与判重 → **不同请求必得不同签名**；**观察有载荷时行为与修复前完全一致**（不引入「换汤不换药」逃避空间）。E2 强切 与 死循环检测**统一改用 `_strategy_signature`**（原先死循环检测内部另一份 `_step_sig` 复制品，只修 E2 会漏——两处必须同源）。
- **端点**：`core/phases.py`（`_plan_fingerprint()` + `observe_step` 注入 `plan_fp`）、`core/main_agent.py`（`StepRecord.plan_fp` / `_strategy_signature` / 死循环检测改调用）。
- **验证**：新增 `tests/test_strategy_signature_no_collapse.py`（9 例：签名语义 / 指纹稳定性 / observe 注入 / 端到端「不同脚本空输出不误杀」+ 对称哨兵「同脚本空输出仍止损」）；**变异验证双向通过**（去掉 plan_fp 分支 → 3 例红；observe 不注入 → 2 例红）；相关套件 **69 passed**（6m29s，含真实 Coppersmith/MHK2 计算）。
- **预期收益**：直接解开「1 题活不过 5 步」的最上游卡点——这是「主链自主 0→≥1」的前置条件（**待下一轮授权跑批 A/B 配对验证**）。
- **KPI 未变**（纯控制流修复，不动任何真值源数字）。
- ⛔ **A/B 验证受阻——本次跑批作废（2026-10-05 16:21，`G_p2b2fix_20261005_162123`）**：真跑进行到中途 DeepSeek 返回 **HTTP 402 Insufficient Balance** → llm.client **熔断**。计数：成功 `200 OK` **12** 次 / `402` **3** 次 / 熔断跳过 **316** 次。⇒ 5 题仅第 1 题（idea）拿到少量真实调用（34,343 token），其余 4 题 token 均 = **1,806**（纯开销、**零真实 LLM 调用**）。报告的 `0/5` 与 `by_error=wrong_direction×3+extract_fail×2` 全是「LLM 返回空 → observation 空 → 签名判重」的人工产物，**不得引用**；已在该目录落 `_INVALID_余额耗尽.md` 标记。**架构修复的真实效果仍未验证**。
- 🔴 **暴露评测框架缺口**：`integrity.interpretable=true` / `mechanism_terminated=0` **未识别 provider 熔断**——把「316 次调用被跳过」当成「已尝试未解出」。建议：provider 永久故障（401/402/403 熔断）应计入 `mechanism_terminated` / 令 `interpretable=false`，否则「余额耗尽」会被静默当成「能力不足」。（**待修复，未改**）
- 🔴 **预算硬约束**：DeepSeek 账户余额已耗尽 → **在充值或换可用 provider 并获授权前，无法再进行任何真跑**。
- 🟡 **换免费源 + 受控 A/B（2026-10-05 16:5x–17:1x，用户「用千问那个免费的」→ 探针实测后改选 tokenhub）**：
  - **provider 探针（¥0）**：`qwen`(DashScope) = **HTTP400 账号状态异常/欠费**（7 模型全挂，含 qwen-flash/turbo 免费档）；`deepseek`=402、`baidu`=403、`glm`=429、`siliconflow`=402；**存活＝ark / tokenhub / xfyun / moonshot**。→ 用户选定 **tokenhub**。
  - 🔴 **二次踩坑**：tokenhub 免费档**只有轻量 `hy3`**；`attempt≥2` 升级到的重型 `deepseek-v4-pro` **需后付费→402**，而熔断器是 **provider 级** → 一次 402 把整个 provider 判死（321 次跳过）。**修法**：启动器把 `CTF_AGENT_TOKENHUB_{HEAVY,MODEL}` 双双钉到 `hy3`（¥0 绕过）。
  - **受控 A/B（同模型 hy3、同 5 题、同配置、冷黑板；唯一变量＝本修复）**：两臂各 1 次运行（各约 20 min，¥0）。
    | 指标 | 修复后(fix) | 修复前(prefix) |
    |---|---|---|
    | 解出 | 0/5 | 0/5 |
    | by_error | wallclock×4 + budget_exceeded×1 | race_abandon×2 + wallclock×2 + budget_exceeded×1 |
    | mechanism_terminated | 1 | 3 |
    | wallclock 截断 | 4 | 2 |
    | token | 192,992 | 312,078 |
    | **行为计数（步/监督/幻觉/兜底）** | **38/10/7/29** | **38/10/7/29（完全一致）** |
  - 🔴 **诚实结论＝该 A/B 在 hy3 上是「干净零结果」**：两臂**死循环判定全为 `reason`、`script` 塌缩两臂均未出现** → **修复针对的病理在此模型上根本不发作**；两臂行为计数逐项相同（hy3 近似确定性解码）→ **修复在本模型上行为惰性、未带来任何解出增量**。
  - ⇒ **修复仍是「正确但潜伏」的缺陷修补**（单测+双向变异背书）；**其收益无法在唯一可用的免费模型上演示**——要验证需「会触发空输出的模型（deepseek）」+「多次重复以取得统计功效（n=5、单次运行无功效）」。
  - 🔴🔴 **更重要的旁证**：即便有可用的 LLM、每题 300s 墙钟 + 40–90K token，hy3 仍 **0/5** → 再次坐实「**钱/时间/这条架构缺陷都不是瓶颈，模型能力才是**」。
  - **两处框架缺口（待修，未改）**：① provider 熔断（401/402/403）未计入 `mechanism_terminated`、`interpretable` 未置 false；② 熔断粒度是 **provider** 而非 model，一个付费模型的 402 会连带杀死同源免费模型。
  - 证据：`data/results/heldout/G_p2b2fix_tokenhub_20261005_163543/` 与 `G_p2b2prefix_tokenhub_20261005_165820/`（gitignored）；日志 `data/results/_ab_{fix,prefix}_hy3.log`；两次被 402 污染的跑批已落 `_INVALID_*.md` 标记。

### 三之三补三、轻量模型覆盖失效修复 + qwen 受控 A/B（2026-10-05，¥0）

- **🔴 key 根因（用户纠正，已证实用户正确）**：上一轮把 qwen 的 `HTTP400 Access denied, account not in good standing` 误判为「账号级封锁」；实际是环境变量 `DASHSCOPE_API_KEY` 里装的是一把**坏 key**（`sk-ws-H.PMPEYIE.…`）。用户给出的活 key（`sk-ws-H.PREIRXE.…`，全长记于 `.workbuddy/memory/2026-10-04.md:188`）复测 **6 模型全 200**。教训：**provider 报「账号异常」先怀疑 key 取值来源**，别急着给 provider 判死刑。
- **🔴 轻量模型覆盖失效（A/B 二度作废的真因，本次修真）**：
  - **根因**：`run.py:167` 主链路 `model = model_override or get_model_for_attempt(attempt, provider)` **显式传 provider** → 命中 `llm/client.py:552` 的 **provider 分支**，其 `attempt < upgrade_after_attempts(2)` 时 **直接 `return default_model`**（= `_resolve_provider_defaults(provider)[1]`），**既不读 `CTF_AGENT_{PROVIDER}_MODEL` 也不读 `CTF_AGENT_LIGHT_MODEL`**。→ 启动器把 qwen「钉到免费档 `qwen3.7-plus`」被**静默丢弃**，仍打默认 `qwen3.7-flash`（其免费额度耗尽）→ 403 → provider 级熔断 → 整轮作废。（`_resolve_settings` 本会尊重该 env，但 `model` 已被 `run.py` 填成非空 → 永不触发。）
  - **修法**：provider 分支 attempt<upgrade 时先读 `CTF_AGENT_{PROVIDER}_MODEL` 再回退 default；与 `_resolve_settings` 优先级一致（专属 env > provider 默认）；仅在显式设置该 env 时生效，**不改变** attempt≥upgrade 无重型可升时回退 default 的既有语义。
  - **提交**：`fbd9449`（实现）/ `e9f5bfe`（回归测试，7 例；变异验证：去修复→2 例红）。
  - **端点证据**：探针 `get_model_for_attempt(0,'qwen')` 由 `'qwen3.7-flash'` → `'qwen3.7-plus'`。
- **✅ 顺带修复 shipped 回归**：`76d0450`（presolve sha256 权威旁路，**已推送**）引入后，`tests/test_qr_matrix.py::test_default_flag_pattern_blocks_nonflag_prefix` 因构造题面带**匹配真值哈希** → 被正解放行 → 全量套件 **1 failed（928 passed）**。修正＝该用例改用 `flag_sha256=None` 纯隔离诱饵守卫 + 新增对称锁 `test_sha256_bypass_releases_real_flag`（锁 76d0450 行为防回退）；变异验证：禁用 `_matches_expected_sha256` → 新锁红。提交 `3fc23f1`（测试）。**全量套件回到全绿（929 passed / 16 skipped）**。
- **受控 A/B（qwen3.7-plus 双钉、同 5 题、同配置、冷黑板；唯一变量＝策略签名修复）**：
  | 指标 | 修复后(fix) | 修复前(prefix) |
  |---|---|---|
  | 解出 | 0/5 | 0/5 |
  | by_error | race_abandon×3 + budget_exceeded×2 | race_abandon×3 + budget_exceeded×2 |
  | mechanism_terminated | 5 | 5 |
  | token | 416,586 | 368,141 |
  | 步数 / 强切 / 幻觉步 | 84 / 7 / 15 | 71 / 7 / 15 |
  | `同参数重复（script）` | 6 | 1 |
  | `同参数重复（reason）` | 0 | 0 |
- **诚实结论**：
  - 两臂 **0/5 且 by_error 完全一致**；`强切(7)`/`幻觉步(15)` 两臂相同，仅步数(84/71)与 `script` 死循环数(6/1)有差。**该差异方向与预期相反**（修复本应减少 script 塌缩误判），且 **n=1 次运行/臂 + qwen 温度 0.1 仍非确定**（E2 强切会改写提示词→轨迹随之分叉）→ **不可归因于本修复**，**A/B 对修复收益仍无正向证据**（与 hy3 上「干净零结果」一致）。
  - 🔴🔴 **第三次坐实瓶颈归因**：deepseek（作废）/ hy3（0/5）/ **qwen3.7-plus（0/5）**三模型一致 0 解出，且每题烧到 **74–91K token ≈ 满预算**才停 → **钱/时间/这条架构缺陷都不是瓶颈，模型能力才是**。
  - 两句框架缺口仍在（provider 熔断未计入 `mechanism_terminated` / 熔断粒度为 provider 而非 model）——本次 fix 臂 `mechanism_terminated=5` 说明 race/budget 已正确归类，但熔断类仍未识别（本次两臂均无熔断，故未复现）。
- 证据：`data/results/heldout/G_p2b2fix_qwen_20261005_181603/` 与 `G_p2b2prefix_qwen_20261005_183233/`（gitignored）；日志 `data/results/_ab_{fix,prefix}_qwen_plus.log`；两次 qwen 污染跑批（`..._174809` 免费额度耗尽、`..._175830` 覆盖失效仍打 flash）已落 `_INVALID_*.md` 标记。

### 三之三补四、provider 熔断根因回填修复（2026-10-05，¥0）

- **🔴 缺口（前序两处框架缺口之①，已坐实但未改）**：`llm/client.py:293-296` 当 provider 熔断（连续 3 次 401/402/403，`_PROVIDER_CIRCUIT_FAIL_LIMIT=3`）打开时 `ai_chat` 直接返回 `None` → 主 Agent 退化成 `race_abandon` / `budget_exceeded` / `solver_exception` 等自身失败模式 → 报告 `summarize`（`benchmark.py:273-291`）把这类计入 `MECHANISM_TERMINATED` 且 `interpretable=True` → 被误读为「Agent 能力失败」。**真因是基础设施（账号/余额/key）不可达**。
- **🔴 实证触发**：2026-10-05 DeepSeek 余额耗尽（402）与 qwen 坏 key（403）两次跑批均触发 provider 级熔断，4–5 题**零真实 LLM 调用**却被报告为 `mechanism_terminated=0` + `interpretable=True` + `by_error=wrong_direction×3+extract_fail×2`（空返回的人工产物），**把「基础设施不可达」粉饰成「已尝试未解出」**。
- **最小诚实修复（¥0，失败开放）**：
  - `core/error_taxonomy.py`：`TRUNCATED_ERROR_CATEGORIES` 新增 `provider_circuit_open`（→ 报告层 `interpretable=False`，不污染能力率）；新增常量 `PROVIDER_CIRCUIT_OPEN` 与 `relabel_circuit_breaker(error_category, circuit_open)`——仅当 `circuit_open=True` 且原桶 ∈ `{race_abandon, budget_exceeded, solver_exception}` 时回填为 `provider_circuit_open`；`None`（已解出）/ `provider_error` / `hallucination` 等原样返回；`circuit_open=False` 原样返回（不误伤）。`NON_RETRYABLE_CATEGORIES` 注释明确不含此类（**不改重试层短路语义**）。
  - `run.py` `build_solver` 的 `solver(q, attempt, correction=None)` 内，`loop.run(...)` 之后、P0 真值仲裁之前插入回填块：读 `provider_circuit_open(provider)`，若真则把终态桶回填并改写 `detail=「provider=... 熔断(401/402/403)已打开，根因为基础设施不可达，非 Agent 能力失败；原终态=...」`。presolve 直出（`error=None`）不受影响。
- **测试**：`tests/test_error_taxonomy_circuit.py`（10 例：7 直接 + 3 参数化）——`PROVIDER_CIRCUIT_OPEN in TRUNCATED_ERROR_CATEGORIES`；`relabel_degraded_bucket_when_open[race_abandon|budget_exceeded|solver_exception]`；`relabel_noop_when_closed[...]`；`relabel_solved_none_open`；`relabel_provider_error_open_unchanged`；`relabel_hallucination_open_unchanged`。**变异验证**：临时 `return error_category`（MUTANT）→ 3 例 `test_relabel_degraded_bucket_when_open` 红 → 还原。
- **提交 SOP（门禁⑫ 拆两次）**：`1315087`（实现）+ `0fc3399`（测试）；六门禁全绿（密钥/诚实/租约 scope 4 元素/快速回归 152 passed/文档一致性/反注水/结构守卫/测试文件守卫）。全量 pytest **940 passed, 16 skipped**（含本段 10 例）。
- **SSH 推送**：推送前 `ls-remote` 复核远端 `main=d76d82d`（非 stale）；`git push git@github.com:TrueFurina/xihu-sword-ctf-agent.git master:main` → `d76d82d..0fc3399` EXIT=0；推送后 `ls-remote` 复核远端=`0fc3399adfc9739a01ea1cb7dac349d084245585`；`update-ref refs/remotes/origin/main` 同步本地视图，`rev-list --left-right --count origin/main...HEAD = 0 0`。
- **诚实口径**：本修复只改变「熔断致 0 解出」的**归因标签**（基础设施不可达，非能力失败），**不改变任何解出数 / KPI**（`offline_verified=14` / `real_corpus=93` / `heldout_candidates=2` / `skills=62`）。阻断了「把熔断粉饰成能力失败」的口径漏洞——与 10-04「诚实口径铁律」一致。

### 三之四、10733 数据缺口处置 —— ✅ 已补齐（2026-10-03）

- **缺口**：台账计 10733 为 ✅ offline_verified，但 `data/race_details/10733.json`、`race_attachments/10733_*`、`data/questions_real/` 条目**三者皆缺** → `_kpi_leak_crossaudit` 报 `missing_corpus=1`。
- **补法（非编造）**：① 从归档 `_archive/ctf_agent_broken/data/race_details/10733.json` 恢复原始平台元数据；② 从元数据里的**原始 DASCTF 资源 URL** 下载官方附件 zip（873 B，内含 `task.py`，字节级确认仅含占位 `******`，**不含真 flag**）；③ 新建 `data/questions_real/crypto/10733.json`——`id="10733"`（与 `_antifraud.BASE_AUTHORIZED_KPI_SOLVES` 对齐，故仍被正确排除出 held-out），`flag_sha256` 由 `verify_10733.py` 的攻击链**复算**并与台账前缀 `ac232bd941738e22` 逐字一致。
- **结果**：`missing_corpus` **1→0**；`real_corpus` **92→93**（覆盖 14/93=15.1%）；README 中英同步。

---

## 四、行动清单

| # | 动作 | 归属 | 成本 | 验收标准 |
|---|---|---|---|---|
| 1 | ~~P0-3 KPI 口径收口（canonical 不再输出过期数）~~ | **✅ 已完成**（终值依据由 10-01 独立复现坐实；`ad61c8b` 首修、**`099011b` 补修摘要行裸引 + 硬编码分母 92**、`0dc1bcc` 护栏入 CI） | ¥0 | canonical 输出分母取自机器真值；历史作废数与作废标记**同行**；两处若有回退即红 |
| 2 | ~~P0-4 跑批默认值 fail-closed~~ | **✅ 已完成**（`eval/benchmark.py` `d51fdae`；`benchmark_heldout.py` `c37efe1`/`d94bca3`；存活单源 `e498be8`/`9458606`） | ¥0 | 真跑无 provider 即拒绝；可用性只查 `logs/llm_probe` 新鲜快照 |
| 3 | ~~P0-2 `test_file_guard.py` 入库~~ | **✅ 已完成**（提交 `834bffd`） | ¥0 | 新克隆钩子可跑通，不再拦死提交 |
| 4 | P0-1 `2027-prep` 排除或归档（M2 先迁出） | **需你拍板** | ¥0 | `git add -An` 从 6854 降到个位数 |
| 5 | NYU 池 5 题大模型试跑 | **需你授权**（且须先完成 #2） | per_q 80K / global 80 万 token；deepseek ≈¥1–2；DashScope 免费档（deepseek-v3.1 每模型 1M 免费至 2026-12-05）可近零 | 5 题真实解出数 + token 账；**不与"分母 2"混算** |
| 6 | 推送本地提交到远端 | **✅ 已授权**（用户 2026-10-03「最后再推」） | ¥0 | 远端 `main` 追上本地、不丢提交、不 `--force` |
| 7 | 工程资产移交清单（框架能力、可迁移件、局限与已知坑） | **✅ 已完成**（`deliverables/规划手册/工程资产移交清单-2026-10-03.md`，本地保留不入库） | ¥0 | 与 KPI 真值源数字一致，不美化；**2026-10-03 02:38 已按真值源 + 代码实测校正漂移**（real_corpus 92→93、runnable_pool 17→41、覆盖率 15.2%→15.1%、presolve `_try_` 53→24、pytest 813→830p/16s、推送状态改「已推送」） |

---

## 五、待你拍板（按依赖顺序）

1. ✅ **口径终值** — 已按「标注作废」执行（提交 `ad61c8b`）：真值源输出改为带更正说明，中英 README 顶置更正声明，原文按项目规矩逐字保留为历史记录。
2. ✅ **跑批授权** — 已执行：NYU 分层 5 题，实耗 **161,604 token（≈¥0.6–1.3）**，结果 **0/5**（详见第二章之二）。
3. ✅ **竞赛遗留归档** — gitignore 非破坏性收口（提交 `596b056`）+ 未跟踪残留归档入库（提交 `0d5ad75`）：`git add -An` **6854→0**，工作树完全干净。是否再把 4 份已跟踪文档迁走仍可由你决定：注意 `M2_E3对照` 是 E3 定调的引用源，有持续价值，**须先迁到中性目录再归档其余**，不可随目录整体掩埋。
4. ✅ **未推送提交** — 用户 2026-10-03 明确授权「最后再推」（豁免 10-01「不推送」）：本地领先远端 **22** 个提交（本会话占 5 个），逐条核验全部属他人/多会话；推送前发现远端另 3 个文档提交（分叉）→ **合并** `ad8a17c` 后经 **SSH** fast-forward 推送（**无 `--force`**），`ls-remote` 复核远端 = `ad8a17c`。
5. 🟡 **是否继续扩样**：下一批再来 5 题（约 ¥1），每批单独授权；扩到 17–20 才算有统计意义，且须用独立字段、不得与分母 2 混算。

---

## 六、禁区（后续会话别踩）

- ~~❌ 任何参赛 / 报名窗口 / 2027 复办 / 赛事日历检索动作（09-29 终局指令）~~ → **2026-10-03 晚已被用户新指令取代**：「我们做这个就是为了 AICTF（自主智能体赛道）取得好名次」——参赛/备战动作解禁；赛事日历检索改为按需服务备战。
- ❌ 美化能力数字（真值：大模型自主 0/17）
- ❌ 把 0/17 当「能力率」对外——那是**跑池**，能力分母是 **2**（两者混算＝欺骗性比率）
- ❌ 用"14/N"当通过率（14 是人工核验台账数，与 held-out 不相交）
- ❌ `git push --force`
- ❌ **`git add -A` / `git add .`**（会误加未跟踪残留；一律 `git add <具体路径>`）
- ❌ 代他人提交 / 推送（原 3 处他人改动 `git_hooks/pre-commit`/`benchmark_heldout.py`/`test_kpi_canonical.py` 已由各自会话提交；2026-10-08 接管时工作树无他人未提交改动）
- ✅ **残留已归档入库**（提交 `0d5ad75`）：5 项未跟踪残留按 heldout_evidence 目录约定入库——`benchmark_report_glm4flash_nyu5_20261005.json`、`runA_e3off_ext5_20260927_1328/`、`runB_e3off_real2_20260927_1330/`、`plans/付费强模型跑批报价单-20261006.md`；其中 `runB` 报告含**已被 10-01 复跑证伪**的归因（`main_agent_llm solved real_crypto_dnui_keyboard`，实为 presolve）→ 已打 `.SUPERSEDED_llm_attribution_refuted_20261008` 标记 + `PROVENANCE.md` 明令下游不得据此宣称 LLM 自主。`.log` 因 `.gitignore` 排除
- ❌ 删除 `2027-prep` 或其它磁盘文件
- ❌ 未估 token×金额报授权就跑批；未补 fail-closed 默认值就付费试跑

---

## 七、术语附录（一句话人话版）

- **presolve（确定性预扫）**：不花钱的"硬找"——先用规则、字符串匹配直接抠答案，抠不到才交给大模型。（历史 17 题池）里解出的 9 题**全是它干的**。
- **held-out（陌生题）**：拿来考试的题，没参与过任何调优，用来测真实能力。
- **能力分母 vs 跑池**：能力分母＝**2**（只有这 2 道能合法算"能力百分之几"）；跑池＝**41**（2026-10-03 扩池后；历史为 17）。**把 0/N 说成"能力 0%"是把"题更难"说成"能力更低"。**
- **KPI 真值源**：脚本 `_kpi_canonical.py`，所有对外数字必须从这里读，**禁止手抄**。
- **E3 开关**：把附件全文塞给大模型看的开关。实测对"能否解出"**零帮助**，但省约 14% token → 生产默认关、评测强制开，是省钱项不是能力项。
- **canonical（真值源）口径**：对外数字的唯一算法口径，改它等于改所有对外材料。

---

## 八、熔断粒度修复：provider → (provider, model)（2026-10-05，¥0，已完成）

**前序遗留的框架缺口②已收口。**

- **事故**：tokenhub 下 `hy3`（免费）本可用，但 attempt≥2 升级到付费 `deepseek-v4-pro` 得 402×3 → 原按 provider 熔断 → **整个 tokenhub 被判死** → 后续 321 次调用被跳过、整轮作废。
- **改**：`llm/client.py` 熔断键改为 `provider::model`（失败记录/成功重置/熔断检查全线模型级；新增 `model_circuit_open(p,m)`；**保留** `provider_circuit_open(p)` 为「任一模型熔断」宽口径，供 `run.py` 的「基础设施不可达」回填继续用）。`run.py` 竞速池剔除候选改模型级（**事故直接源头**）；`llm/failover.py` 同步（先解析将用模型再判）。
- **测试**：新增 `tests/test_circuit_model_granularity.py` 10 例（含事故复现；**变异验证**：键退回 provider 级 → 核心用例必红）；`test_ai_vision.py` / `test_llm_failover.py` 同步到新 API（**不然是假绿**——补丁失效仍会通过）。
- **提交**：`8f5e7bc`（client 实现）+ `adee193`（新测试）+ `9868693`（failover 实现）+ `1c78004`（既有测试同步），遵第 ⑫ 道分开提交。

---

> 📌 本计划由软件工坊（产品评审员产出 + 主理人汇编，全部结论经磁盘复核）生成，关键决策请项目负责人复核。
