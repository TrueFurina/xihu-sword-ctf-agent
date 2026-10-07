# OCR 多 psm 候选择优修复（psm7 伪命中抢先返回）—— pcap 与 SVG 两条 OCR 链路加固

> 提交：`fix(skills): OCR 多 psm 候选择优（修 psm7 伪命中抢先返回）`（实现）
> ＋ `test(skills): OCR 候选择优行为 + 变异`（测试）→ 本文（文档）
> 日期：2026-10-07 ｜ 成本：**¥0**
> ⚠️ 状态行不钉死 commit 哈希——多会话下 rebase/重放会使其失效（2026-10-07 教训）。

## 结论先行

修复 `skills/svg_path_text.py::ocr_image` 的候选选择缺陷：原实现「按 psm 顺序（7→6）、**首个
含花括号者即返回**」。当 psm7 输出含非可打印字符（如 U+00A7 `§`）的伪命中时，会抢先返回、丢掉
psm6 的正确结果。

实测（CSAW-Quals 2017 forensics `missed_registration` 的 323×39 8bpp BMP，3× 放大后 OCR）：

| psm | OCR 输出 |
|---|---|
| 7 | `| FLAG{anm_LaunDR3Y_FL4E_L34k§_}` ← 含 `§`（非 ASCII） |
| 6 | `FLAG{3Am_LaunDR3Y_FL4G_L34kz!}` ← 正确 |

修前 `P.solve(cap.pcap)` 返回 psm7 的伪命中（sha `887c2993…`）≠ 题面；修后返回 psm6 的正确值
（sha `b0e408d1…`，与题面 `flag_sha256` **逐字吻合**）。

## 为什么这是真问题（而不只是「测试红了」）

- `test_pcap_http_carve.py` 的真题锁与 presolve 端到端测试当时为**红**（`P.solve` /
  `presolve(force=True)` 返回 `None`）。
- 更严重的是**正确性风险**：`_ocr_flag_from_image` 会把 OCR 文本交给 `_FLAG_RE` 提取；含 `§` 的
  候选在**无题面真值**时不会被 sha256 拦下，可能作为伪 flag 上报（`[^}\s]` 对非 ASCII 是宽松的）。
- 影响两条链路：`skills/pcap_http_carve.py`（图片类雕取）与 `skills/svg_path_text.py`（SVG 渲染
  文字）都经 `ocr_image`。

## 改法

抽出两个纯函数（可单测、可变异）：

```python
_OCR_FLAG_RE = re.compile(r"[A-Za-z0-9_]{1,12}\{[!-~]{3,120}\}")

def _ocr_candidate_score(text):
    # 良构 flag（仅可打印 ASCII）> 全 ASCII > flag 更长 > 整体更长
    ...

def _select_ocr_candidate(outs):
    # 并列保留先出现者（保持 psm7 优先的历史语义，避免无谓行为漂移）
    outs = [o for o in outs if o]
    return max(outs, key=_ocr_candidate_score) if outs else None
```

`ocr_image` 改为收集 psm7/6 **全部**候选后交 `_select_ocr_candidate` 择优（不再提前 `return`）。

## 验证清单

- 修前 / 修后 `P.solve(cap.pcap)` 的 sha256 对照（`887c2993…` → `b0e408d1…` = 题面真值）。
- `tests/test_pcap_http_carve.py` **`19 passed`**（含真题 sha256 锁 + presolve 端到端）。
- `tests/test_svg_path_text.py` **`19 passed`**（无回归）。
- 新增 `tests/test_ocr_candidate_selection.py` **`11 passed`**（纯函数单测 + monkeypatch 接线
  断言「两个 psm 都被收集」，零外部依赖）。
- **变异验证**：把 `_select_ocr_candidate` 改为 `return outs[0]`（旧行为）→ 3 个用例转红
  （含核心回归 `test_select_prefers_clean_flag_over_nonascii`）；还原后全绿。
- 回归：`presolve / kpi / leak / skill / honesty / doc / ocr` 目标集全绿；门禁⑥ `152 passed`；
  `_doc_consistency` 绿。

## 口径更正（对既有赛报的影响）

本轮把 `deliverables/复盘赛报/pcap表单切片嵌入文件雕取能力接通-CSAW2017-missed_registration
离线攻破-20261007.md` 的「OCR 端到端 → sha256 逐字吻合」结论**标记为依赖本次修复**：该文提交
时点之后，psm7 伪命中会抢先返回，同一结论在当前环境**不可复现**（已在该文顶部加更正横幅指向
本文）。**答案值本身无误**——修好后逐字吻合。

## 诚实边界

- 这是**使能与正确性修复**，不是解题率提升；两个受影响的真题（`missed_registration`、
  `floating_points`）本就已被 presolve 覆盖。
- 未改动 OCR 引擎本身（仍是可选依赖 tesseract），也未宣称 OCR「可靠」——只是让**已知的多候选
  场景改用更稳的择优判据**。
