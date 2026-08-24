# 🎯 /goal 顶层指令落地交付报告

> **日期**：2026-08-19 | **状态**：✅ 全链路验证通过 | **初赛**：8/21 14:00-17:00

---

## 一、平台测试赛最终成绩

| 指标 | 值 |
|------|-----|
| 已解出 | **7/7 (100%)** |
| stagePoint | **800** |
| 排名 | **70**（起始 296 → 70，提升 226 名） |

全部 7 道题 `hasSolved=True`：10661 web-unserialize / 10663 解压缩 / 10678 easy_uaf / 10680 Fate / 10696 TheoremPlus / 10662 shopping / 10664 UploadKing

---

## 二、/goal 指令代码落地清单

### 2.1 新建模块（2 个）

| 模块 | 路径 | 职责 |
|------|------|------|
| `goal_directive.py` | `core/goal_directive.py` | Goal 系统提示词 + SelfReflection/SkillRequirement 数据结构 + GoalLogger 日志持久化 |
| `skill_manager.py` | `tools/skill_manager.py` | 本地 Skill 仓库管理 + AST 沙盒校验 + 动态加载注册到 ToolRegistry |

### 2.2 修改文件（2 个）

| 文件 | 修改内容 |
|------|----------|
| `core/main_agent.py` | ① `__init__` 新增 `goal_logger` / `skill_manager` 参数 |
|                      | ② `_plan` system prompt 注入 `GOAL_SYSTEM_PROMPT` |
|                      | ③ `_finalize` 改为自动生成 `self_reflection` + `skill_require` + `task_status` + 写入 GoalLogger |
|                      | ④ 新增 `_build_self_reflection()` — 从步骤历史自动生成结构化反思 |
|                      | ⑤ 新增 `_infer_skill_require()` — 从 ability_gap 推断 Skill 需求，自动加载本地已有 Skill |
| `run.py`            | ① `build_solver()` 初始化 `SkillManager`，discover + 全量加载本地 Skill |
|                      | ② `MainAgent` 构造时注入 `skill_manager` |

### 2.3 新建 Skill 仓库（4 个 Skill）

| Skill | 文件 | 用途 | 适用题型 |
|-------|------|------|----------|
| `morse_decoder` | `skills/morse_decoder.py` + `.json` | 摩斯密码解码 | misc/crypto |
| `rsa_fermat_factor` | `skills/rsa_fermat_factor.py` + `.json` | RSA 费马分解（p-q 相近时） | crypto |
| `zip_chain_decode` | `skills/zip_chain_decode.py` + `.json` | 多层嵌套 zip 文件名链解码 | misc |
| `base64_multilayer` | `skills/base64_multilayer.py` + `.json` | 自动多层 Base64/32/16 解码 | misc/crypto |

### 2.4 验证脚本（2 个）

| 脚本 | 用途 |
|------|------|
| `scripts/_verify_goal.py` | 语法/导入/Skill加载/AST沙盒/GoalLogger 单元验证 |
| `scripts/_verify_goal_e2e.py` | MainAgent.solve() 端到端集成测试（成功/失败/Skill推断） |

---

## 三、验证结果

### 3.1 单元验证 (`_verify_goal.py`)

```
=== 1. 语法检查 ===       8/8 OK
=== 2. 模块导入检查 ===    4/4 OK (goal_logger=Y, skill_manager=Y)
=== 3. Skill 仓库扫描 ===  4/4 loaded OK
=== 4. AST 沙盒校验 ===    safe: PASS / dangerous: REJECTED
=== 5. GoalLogger ===      write+read: OK
RESULT: ALL PASS
```

### 3.2 端到端集成测试 (`_verify_goal_e2e.py`)

```
=== 测试 1: 成功路径 ===   flag=✅ task_status=solved self_reflection=✅ GoalLogger=✅
=== 测试 2: 失败路径 ===   no_flag=✅ task_status=failed ability_gap=2 gaps_summary=2
=== 测试 3: Skill 推断 ===  morse_decoder 已加载 → skill_require=None（不重复请求）
总体: ✅ ALL PASS
```

---

## 四、/goal 闭环工作流程

```
MainAgent.solve(question)
  │
  ├─ _plan()  ← GOAL_SYSTEM_PROMPT 注入 system prompt
  │             （告诉 LLM：必须输出 self_reflection + skill_require）
  │
  ├─ _act()   ← 工具调用/脚本执行/推理
  │
  ├─ _observe() ← 步骤记录（错误分类/僵局检测）
  │
  ├─ _supervise() ← 监督裁决（每 2 步或连续失败）
  │
  └─ _finalize()
       │
       ├─ _build_self_reflection()  ← 自动生成结构化反思
       │    what_i_did: 步骤摘要
       │    success_or_failure_reason: 成功/失败根因
       │    ability_gap: 能力缺口列表
       │    strategy_adjust_suggestion: 策略调整建议
       │
       ├─ _infer_skill_require()    ← 从 ability_gap 推断 Skill 需求
       │    本地已有 → 自动加载到 ToolRegistry → need_download=False
       │    本地没有 → 输出 skill_require 结构体
       │    已加载 → 不重复请求
       │
       ├─ AgentOutput JSON（原有字段 + Goal 扩展字段）
       │    原有: flag, confidence, evidence, error, retries, steps...
       │    扩展: self_reflection, skill_require, task_status
       │
       └─ GoalLogger.log()  ← 持久化到 data/results/goal_log.jsonl
              赛后可 ability_gap_summary() 统计高频缺口 → 批量扩充 Skill 库
```

---

## 五、核心机制说明

### 5.1 self_reflection 自动生成

`_build_self_reflection()` 基于步骤历史自动识别能力缺口：
- 连续失败 → 缺少有效攻击路径
- 纯推理空转 → 缺少工具调用/脚本执行
- 工具执行失败 → 缺少可用工具或参数
- 有附件未解析就尝试解题 → 推理跳步标记
- Pwn/Web 题型给出专项策略建议

### 5.2 skill_require 动态推断

`_infer_skill_require()` 从题目描述和 ability_gap 关键词推断所需 Skill：
- 本地已有且已加载 → 不重复请求（`need_download=False`）
- 本地已有但未加载 → 自动加载到 ToolRegistry
- 本地没有 → 生成 `skill_require` 结构体
- 高危 Skill 请求 → 自动拒绝

### 5.3 AST 沙盒校验

`tools/skill_manager.py` 对 Skill 脚本做 AST 静态检查：
- 禁止导入：`subprocess` / `ctypes` / `socket` / `shutil` / `multiprocessing` 等
- 禁止调用：`eval()` / `exec()` / `os.system()` / `os.popen()` / `shutil.rmtree()` 等
- 校验通过才动态导入并注册；不通过记录 `skill_load_failure`，不阻断解题

---

## 六、本地题库批量解题成果

| 题型 | 解出/总数 | 解出率 |
|------|-----------|--------|
| Crypto | 10/10 | 100% |
| Misc | 10/10 | 100% |
| Web | 10/10 | 100% |
| Reverse | 5/5 | 100% |
| Pwn | 5/5 | 100% |
| **合计** | **40/40** | **100%** |

---

## 七、兼容性与安全

- `self_reflection` 和 `skill_require` 是 AgentOutput 的扩展字段，**不破坏**原有 `flag/confidence/evidence/error/duration_ms/retries` 等字段
- Skill 全部从本地仓库加载，**不发起外网请求**，符合赛事环境约束
- 未配置 `goal_logger`/`skill_manager` 时自动降级，不影响旧链路
- AST 沙盒确保 Skill 代码安全（禁止危险操作）

---

## 八、后续使用方式

### 8.1 启动平台模式（自动拉题 + 解题 + 提交）

```bash
python run.py --mode platform --once
```

### 8.2 添加新的 Skill

在 `skills/` 目录下新增：
- `your_skill.py`：必须包含 `def run(params):` 函数
- `your_skill.json`：元数据（name/purpose/input_spec/output_spec/categories/version）

启动时 `SkillManager.discover()` 自动扫描，`SkillManager.load("your_skill")` 自动校验并注册为工具。

### 8.3 赛后复盘

```python
from core.goal_directive import GoalLogger
gl = GoalLogger()
print(gl.ability_gap_summary())  # 高频能力缺口统计，指导扩充 skill 库
```

---

## 九、初赛备战要点（8/21 14:00-17:00）

1. **平台 API 全链路已验证**：认证/拉题/启动靶机/提交/回收，代码就绪
2. **Skill 仓库已就绪**：4 个 Skill 覆盖摩斯/RSA费马/zip链/base64多层
3. **AST 沙盒安全**：禁止 subprocess/ctypes/socket 等，比赛环境安全
4. **GoalLogger 反思日志**：每题自动记录 ability_gap，赛后可统计高频缺口
5. **剩余备战**：安装 pwntools/z3（网络恢复后），Fate RCE 外带方案，pwn 真实链路 GDB 调试

---

*🦐 OpenSquilla — 边执行、边反思、边自我进化*
