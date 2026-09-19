# LLM 破冰基准复测报告（2026-09-01）

> 口径：baidu 千帆 + `--no-internal-presolve`（纯 LLM 真推理，presolve 被 mock 成 None）
> 全量 15 真题，attempts=2，timeout=240s
> 交付物：`ctf_agent/deliverables/llm_breaking_ice_20260901-050201.json`

## 一、结论

**全量 11/15 SOLVED**（基线 8/15，+3），无回归。

### 逐题对比（基线 20260828-105959 → 最新 20260901-050201）

| 题 | 类目 | 基线 | 最新 | 备注 |
|---|---|---|---|---|
| real_crypto_ezmult | crypto | ✅ | ✅ | |
| real_crypto_anwang_crypto1 | crypto | ✅ | ✅ | |
| real_crypto_dnui_keyboard | crypto | ❌ | ❌ | **本次映射修复未翻** |
| real_crypto_exciting_inverse | crypto | ✅ | ✅ | |
| real_crypto_ezrsa | crypto | ✅ | ✅ | |
| real_crypto_filterrandom | crypto | ✅ | ✅ | |
| real_crypto_qiangwang_classic | crypto | ❌ | ✅ | 非键盘类 |
| real_crypto_simplelegendre | crypto | ❌ | ✅ | 非键盘类 |
| real_crypto_specialcurve2 | crypto | ❌ | ❌ | 不可复现 GAP（实例值未留存）|
| real_misc_vnctf_flag | misc | ❌ | ❌ | 视觉/OCR 缺口 |
| real_misc_xuanhun_signin | misc | ❌ | ❌ | 视觉缺口 |
| real_reverse_js | reverse | ✅ | ✅ | |
| real_reverse_sheng | reverse | ❌ | ✅ | 非键盘类 |
| real_reverse_upx | reverse | ✅ | ✅ | |
| real_web_gongye_web2 | web | ✅ | ✅ | |

### 诚实归因（关键）

- **+3 道（qiangwang_classic / simplelegendre / sheng）与本次代码改动无关**：
  这 3 道都不是键盘类题型，4a4b6e4 的键盘映射修复不可能影响它们。其提升来自 **LLM 调用的非确定性 + attempts=2 的随机波动**，非代码确定性改进。
- **我的键盘映射修复（4a4b6e4）未救活 dnui_keyboard**：该行仍 UNSOLVED。
- **无回归**：基线 8 道 SOLVED 全部保持。

## 二、dnui_keyboard 仍失败的根因（最该修的点）

`infer_skill_require`（prompts.py）经 4a4b6e4 已能把 dnui_keyboard 映射到 `crypto_keyboard_path` solver，
结果写入 `skill_require` 字段 + `_last_skill_require`（main_agent.py:971-973）。

**但 `solve` 循环从不消费 `_last_skill_require` 去实际路由执行该 skill 工具**——
它只是被记录下来。LLM 在破冰模式下仍自由选 tool，于是反复跑 `phases.py` 的通用 crypto 确定性链，
从不真正调用 `crypto_keyboard_path`（该 solver 已在 `registry` 就绪列表、且记忆确认对真实附件能解出并 sha256 匹配）。

→ 这是**从"建议"到"强制路由"的缺口**，需改 `core/main_agent.py`（solve 循环消费 skill_require）。

## 三、剩余 4 道 UNSOLVED 分类

1. **dnui_keyboard**：路由缺口，solver 已具备 → **可确定性修**（动核心路由）
2. **specialcurve2**：实例值未留存，不可复现 → 已知 GAP，无解
3. **vnctf_flag / xuanhun_signin**：flag 在图内，需 OCR/视觉模型 → 架构级缺口（文本 LLM 不可解）

## 四、待决策

是否授权改动 `core/main_agent.py` 的 solve 循环，让 `skill_require` 真正路由执行
（强制/优先调用 `crypto_keyboard_path` 等已识别 solver）？该改动属核心执行逻辑扩张，需拍板。
