# 贡献指南 · Contributing

感谢你考虑为 xihu-sword-ctf-agent 做贡献。本项目采用 **deterministic-first** 路线，
治理上坚持三铁律：**工件可信、裁判分离、启动即门禁**。

## 你可以从哪里入手

- **Good first issues**：仓库 Issues 中标记为 `good first issue` 的条目（确定性技能扩展、文档、测试）。
- **路线图**：`help wanted` 标签下是真实工程任务（见 README 路线图）。
- **新确定性技能**：在 `skills/` 下按 `run(params)->dict` 接口新增，必须可复跑、可审计。

## 提交前自检（本地门禁）

```bash
bash setup.sh                                  # 建 venv + 依赖 + 全测试
python -m pytest tests/ -q -m "not slow"       # 离线测试门禁（失败即阻断）
python scripts/_honesty_scan.py               # 诚实水位扫描（拦截虚假战报表述）
```

## 提交纪律

1. **不虚报水位**：commit message / 文档不得写「解出数 0→N」「真实解出 flag」等虚假战报。
   诚实扫描器会拦截，CI 也会跑它。
2. **确定性优先**：能用静态分析/脚本解决的，不要引入 LLM 黑盒路径。
3. **不带入密钥**：任何 `sk-` / `ghp_` / `AKIA` 格式字符串会被预提交钩子与发布脚本拦截。
4. **内部资料不入仓**：`data/results/`、`docs/internal/`、作战复盘、未脱敏报告均不提交。

## PR 流程

1. fork → 建 `feature/xxx` 分支 → 小步提交。
2. 确保本地门禁全绿。
3. 开 PR，描述「解决了什么、验证方式、是否动了确定性/LLM 边界」。

我们欢迎真实、可追溯的改动；模板化灌水 PR 不会被合并。
