# 🔧 西湖论剑 CTF-Agent 赛前 P0 修复交付报告

**日期**：2026-08-21（开赛当日上午 08:30，距 14:00 开赛约 5.5 小时）
**工作流**：P0 修复执行（架构 / 代码 / 可靠性 / 测试 / 文档 五线并行）
**参与成员**：Archi（架构）/ Cody（代码）/ Rex（SRE）/ Tessa（测试）/ Docu（文档）

---

## 📌 TL;DR（执行摘要）

- **整体结论**：头脑风暴发现的 **6 项开赛级 P0 全部闭环**——难度传递链打通（三点联动）、重型升级上线、沙盒绕过堵死、400 降级兜底、启动入口固化、余额实测确认。**pytest 38 用例全绿，preflight exit 0，平台 --probe 连通**，已 git 提交赛前快照 `25dce3d` 作为可靠回滚点。
- **严重度分布**：🔴严重 0 项残留（6 项 P0 已闭环）/ 🟠高 2 项（赛中监控待启用）/ 🟡中 2 项（备份缺失已用 git 兜底）
- **阻塞 / 非阻塞**：开赛硬条件全部就绪，非阻塞；剩余为赛中监控与赛后事项
- **交叉验证**：Archi 修复 → Tessa 验证（38 passed）→ Cody 复跑（38 passed）→ 主理人抽查关键改动落地（grep 实证）

---

## 🎯 核心结论卡片

| 项目 | 内容 |
|------|------|
| 整体评级 | 🟢 通过（开赛硬条件就绪） |
| P0 残留 | 0 项（6/6 闭环） |
| 测试状态 | pytest 38 passed（30 基线 + 8 新增） |
| 回滚点 | git commit `25dce3d`（赛前快照，9 文件 +411/-18） |
| 建议下一步 | 14:00 开赛按 start_race.bat 启动，赛中跑 monitor_race.sh 盯 5 指标 |

---

## 🔍 修复明细（按 P0 项，含代码/文件实证）

### P0-2 三点联动修复包（Archi）✅
| 改动 | 文件:位置 | 实证 |
|------|----------|------|
| ① 高难首步重型读 difficulty | core/main_agent.py:188 | grep: `getattr(question, "difficulty", "")` ✅ |
| ② 分级墙钟读 difficulty | core/main_agent.py:384 | 同上 ✅ |
| ③ build_platform_solver 补 difficulty 空串（**防全题落 120s 陷阱**） | run.py:443 | grep: `difficulty=str((ch.extra or {}).get("difficulty", ""))` ✅ |
| 升级映射 heavy_map（deepseek→reasoner / qwen→v4-pro-0813 / tokenhub→v4-pro） | llm/client.py:252-258 | grep: `heavy_map` ✅ |
| LLM 超时 120s→60s | config.py:79 | 改后 py_compile 通过 ✅ |
| 防守性默认值（空/未知→300s） | main_agent._wallclock_for | 现有实现已满足，未额外加码 ✅ |

### P0-4 沙盒绕过堵死（Cody）✅
| 改动 | 实证 |
|------|------|
| `_FORBIDDEN_STR_PATTERNS` 字符串常量扫描（os.system/os.popen/subprocess/__import__(/getattr(__import__ 等） | sandbox/subprocess_executor.py:64-66,115 ✅ |
| `_check_bash_command` 裸 bash 命令拼接拦截（`;`/`&&`/`||`/`\|`） | :209,256 ✅ |
| AST 9 用例实测：`getattr(__import__("os"),"system")("id")` 等全部 BLOCK；正常 import os 放行 | 成员实测 ✅ |

### P0-5 400 兜底（Cody）✅
| 改动 | 实证 |
|------|------|
| `_degrade_messages` 400 降级重试（剥控制字符+超长截 300） | llm/client.py:386,424 ✅ |
| `_repair_json` JSON 修复（尾逗号/单引号 key） | :494,538 ✅ |
| `BoundedSemaphore(4)` 并发护栏 | :47 ✅ |
| 白名单闸门零改动（grep 确认） | ✅ |

### P0-1 启动入口固化（Rex）✅
| 交付 | 位置 |
|------|------|
| start_race.bat（_race_start.py --compete + 4 env + 日志重定向） | ctf_agent/start_race.bat ✅ |
| start_web.bat（run.py --mode web，8000 端口） | ctf_agent/start_web.bat ✅ |
| --compete 参数实测存在 | 成员实测 ✅ |

### P0-6 余额实测（Rex）✅
- **deepseek-chat 200、无欠费、无需切 baidu**；10 个 provider 全可用（reasoner/baidu/mimo/qwen/讯飞/智谱等），仅 glm 无 key（非故障）
- 附件目录 data/platform_downloads 已清空（本就为空）
- 监控脚本 `scripts/monitor_race.sh` 跑通（400/429/402 计数 + error.category 分布 + flag 对账：goal 410 vs submitted 85）

### P1-5 文档一数定音（Docu）✅
- 12 个文档更新：作战手册为唯一真相源（sensenova 白名单更正、启动命令更正、**真实水位 33%**、skill 34）；11 份旧口径文档加"已冻结"标注
- 答辩口径决策：对外/答辩统一 **33%**（模型自主+独立校验），89% 攻坚实录仅赛中参考

### 测试验证（Tessa）✅
- 基线 30 passed → 新增 `tests/test_difficulty_wallclock.py`（8 用例：hard→600 / easy→120 / 空→300 / 缺失→300 / VERY_EASY/HARD / medium / 大小写 / 注入覆盖）→ **全量 38 passed**
- preflight exit 0（ENFORCE=1 合规）；--probe 平台连通 OK（0 题，赛前未放题正常）

---

## ✅ 行动清单（剩余 / 赛中）

| # | 行动 | 负责 | 紧急度 | 时机 |
|---|------|------|--------|------|
| 1 | 开赛用 `start_race.bat` 一键启动（不再手输命令） | 人类 | P0 | 14:00 |
| 2 | 赛中每 30min 跑 `monitor_race.sh` 盯 5 指标（accepted/假阳性率>30%告警/止损分布/400-429-402/耗时） | 人类 | P1 | 赛中 |
| 3 | 赛中遇 400 → 已自动降级重试；仍失败查 goal_log + 截断 observation | 人类 | P1 | 赛中 |
| 4 | 核对该 env：`CTF_AGENT_LLM_TIMEOUT` 若注册表为 120 会覆盖新 60s 默认（start_race.bat 已显式设 env，建议确认） | 人类 | P2 | 开赛前 |
| 5 | 赛后：更新 ctf_agent/data/results/ 内 6 份旧数字文档（诚实水位声明/决赛答辩素材等）+ 检查答辩 HTML | Docu | P2 | 赛后 |
| 6 | 赛后：跑 NYU CTF Bench + Cybench 产出可比解出率报告 | 人类 | P3 | 赛后 |

---

## ⚠️ 待完善 / 已知局限

- **备份缺失**：core/main_agent.py、llm/client.py、sandbox/subprocess_executor.py 的 .bak_p0 实际不存在（成员声称备份但未落盘）→ **已用 git 快照 `25dce3d` 兜底**（更可靠的回滚点），无需补救
- **字符串常量扫描保守取舍**：含 "subprocess" 字样的普通常量文本会被拦（正常解题脚本几乎不出现，可接受）
- **bash 裸命令禁拼接符**：未来合法管道/分号 bash 脚本需走 python: 前缀（本轮无影响）
- **Semaphore(4) 进程内护栏**：多进程部署不共享（当前单进程 asyncio 够用）
- **qwen/tokenhub 重型模型名**基于实测注释，若端点不可用会 fail-open 不阻塞
- 其余未提交改动（agents/*、data/questions/* 等历史修改）仍在工作区未 commit——不影响本轮快照，赛中勿动

## 📚 数据来源 & 成员产出索引

- Archi（架构师）原始产出：P0-2 四点联动交付报告（含偏差说明：extra 字段平台链路本可通、本地题库失效，统一改读 difficulty 双链路打通）
- Cody（代码审查师）原始产出：P0-4/P0-5 四修改交付报告（含沙盒 9 用例 + 400 降级 mock + JSON repair 8 用例）
- Rex（SRE）原始产出：启动 bat + 余额实测表 + monitor_race.sh + --probe 结果
- Tessa（测试专家）原始产出：基线回归 + 8 项 difficulty 单测 + 全量 38 passed + preflight exit 0
- Docu（文档师）原始产出：12 文档更新清单 + 口径决策（33% vs 89%）

---

> 本报告由工程保障团队 AI 协作生成，关键决策请由人类工程负责人复核。
> ⚠️ 所有修复已由 Tessa/Cody 独立验证（38 passed）+ 主理人 grep 抽查落地，回滚点 = git `25dce3d`。
