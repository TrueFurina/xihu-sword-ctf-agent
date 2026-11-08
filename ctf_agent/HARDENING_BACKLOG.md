# CTF-Agent 备战加固清单（数据驱动）

> 复核日期：2026-11-08 ｜ 数据源：`data/results/goal_log.jsonl`（473 条）
> 方法：逐条解析 `self_reflection.what_i_did` / `ability_gap` / `success_or_failure_reason` 正确字段
> 时间轴：全部记录时间戳均晚于 2026-10-21（空转升级机制上线日），故"机制已生效"假设可被实证检验。

## 一、推翻前几轮误判

| 误判 | 真相（正确字段下） |
|------|------|
| "262 unresolved 全是零工具调用" | 记录**无 `steps` 字段**，该统计是字段读错假阳性。真实：`what_i_did=无步骤记录` 130 条(27%)，其余有混合步骤 |
| "P1 门禁已落地不必重做" | 机制存在但有**缺口**：纯推理空转在**无附件/无探针时无恢复路径**（见 P1） |
| "42 条幻觉是文本匹配误报" | `last_error=hallucination` 确为 42 条，真实存在，属漏网 |
| "343 crypto 缺附件是次要项" | 它是**头号问题**（占 gap 提及 343/602），但属测试环境未提供题包，真实 CTF 提供附件后自动消解 |

## 二、真实根因（按影响排序）

- **P0 · 附件/靶机缺失（gap 提及 382 次，结构化统计；原 backlog 写 343 偏低）**
  crypto/reverse/misc 题型缺少附件或靶机交互。离线测试未提供题包。
  → 真实 DASCTF 必带附件/靶机，此项自动消解；但需确认 harness 把 `attachments`/`target` 真正注入 agent 上下文。

- **P1 · 纯推理空转无恢复路径（107 纯推理空转 + 52 wallclock_timeout 全在 t1）**
  `_force_deep_probe`(`core/main_agent.py:211`) 检测到 reason-loop 后，**仅当存在适用探针(rea_probe/wasm_probe/pcap_probe)且有附件时才强制调用**；
  无附件时 `_pick_probe_target` 返回 None → `main_agent.py:263-264` 直接 `return None`，**无兜底**。
  agent 在 `reason→reason→reason` 中烧完 80k token 预算，最终 unresolved / timeout。

- **P2 · 幻觉漏网（⚠️ 复核后判定为「第 4 处误判」，已撤销）**
  原 claim：`extract_flag` 三态证据门未覆盖"纯推理直接断言 flag"路径，42 次幻觉 flag 未被拦截。
  **复核结论（2026-11-08，结构化字段核验）**：
  - 全库 473 条记录 `last_error` 字段**恒为 None**——根本不存在 `last_error=hallucination` 结构化字段；
    那 42 条是「全文含 hallucination 关键词」（`self_reflection.success_or_failure_reason` 里写
    "last_error=hallucination" 这是**字符串日志**，非字段），与本节自己声称已排除的"文本匹配误报"同型。
  - 这 42 条 `validated` 全为 False、`flag` 字段全空、`error.category=wrong_direction`、
    `what_i_did` 全是 `reason;reason...` → **extract_flag 证据门已正确拦截**（置 `_extract_failed`、
    计 hallucination strike），**零 flag 漏到平台**（全库 `validated=True` 计数为 0）。
  - 这 42 条实为 P1（107 纯推理空转）的子集，非独立泄漏路径。
  - 代码侧再证：33 项反幻觉单测全绿（含变异测试，证明 provenance 闸真能拦
    `no-tool-evidence` / `print-leak`）；`extract_flag` 四分支（checker/正则/宽sha256/E1）全过
    sha256 仲裁或 `provenance_allows`；直接 `candidate_flag` 赋值（main_agent:1124/1186）均来自
    `registry.run` 真实工具 observation，属合法工具来源。
  → **结论：P2 要求「所有 flag 断言经 extract_flag 三态校验」已被满足，无需任何代码改动。**

- **P3 · 题型零解出（reverse 0/39、misc 0/26）**
  与 P0 同源（缺附件/靶机）+ 可能缺专用技能覆盖。

## 三、加固路线（分级）

### P1（代码·加性·低风险）— 已实施（强提示注入）
新增 `_apply_reason_loop_fallback(agent, ctx)`（`core/main_agent.py:193`），在 reason-loop
检测分支、且 `_force_deep_probe` 因无附件/无适用探针而 return None 时：
- 注入强提示（`advisor_hint`），要求改用 `script`（python 沙盒）/ `http_request` 拿真实证据，禁止纯推理空转；
- 去重靠 `ctx.reason_escalated`（动态属性，默认 False），探针已生效则交还 `_force_deep_probe`。
- 调用点：`core/main_agent.py:932`（空转恢复块内，`_force_deep_probe` 之后）。
- **早退/预算保护**：已由主循环既有墙钟硬止损（300s）与预算硬顶覆盖，**无需改动终止语义**，避免引入回归。

### P1 验证
- `python -m py_compile core/main_agent.py` 通过；两处改动落位（193 函数 / 932 调用）。
- 回归需真实带附件题；预期纯推理空转（107）在"有附件+探针"真实场景下降至接近 0（探针本就强制），
  离线无附件场景则由墙钟兜底不再空烧 80k token。

### P2（代码·核查 → 结论：已满足，无需改动）
`extract_flag` 四分支（checker/正则/宽 sha256/E1）全过 sha256 仲裁或 `provenance_allows`；
直接 `candidate_flag` 赋值（main_agent:1124/1186）均源自 `registry.run` 真实工具 observation，合法工具来源；
33 项反幻觉单测（含变异测试）全绿证明闸门有效；数据侧 42 条「幻觉」记录 `flag` 空、`validated=False`、
`error_struct.category=wrong_direction` → 闸门已正确拦截，**零泄漏**。P2 要求已被满足。

### P0（harness）
跑真实题前确保 `attachments`/`target` 注入 agent 上下文；无附件且无靶机时直接结构化早退，不进入推理。

### P3（技能）
补齐 reverse / misc 专用探针与技能覆盖。

## 四、验证方式
- 用 `flag{ok}` 练习靶 + 真实带附件 crypto 题回归；
- 对比 473 条基线（全为离线未验证练习，`validated` 全 False）：候选提取 52（非确认解出）、unresolved 262、wallclock_timeout 52；
  ⚠️ 原「hallucination 42」已从基线移除——其为 `self_reflection` 文本含词、且 `flag` 空/`validated=False` 的**闸门正确拦截**记录，非泄漏；
- 目标：P1 落地后纯推理空转（107）与 wallclock_timeout（52）显著下降。
