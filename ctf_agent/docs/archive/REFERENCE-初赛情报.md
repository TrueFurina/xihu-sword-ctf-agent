# 📋 西湖论剑初赛官方情报 + 选手群实战精炼（REFERENCE）

> **来源**：第九届西湖论剑初赛参赛手册.pdf（官方权威）+ 选手群³分析报告（1914 条消息实战情报）
> **整理日期**：2026-08-18 23:30 ｜ **初赛**：8/21 14:00-17:00（剩 2.5 天）

---

## 一、时间硬约束

| 节点 | 时间 | 状态 |
|------|------|------|
| 测试赛 | 8/18 09:00 - 8/19 17:00 | ⏳ 进行中（剩 ~18h） |
| 初赛 | **8/21 14:00-17:00**（3 小时） | 待办 |
| 晋级名单 | 8/31 前 10:00 | 前 12 名进线下决赛 |
| 线下决赛 | 9 月底前 | 现场演示 + 代码审查 + 技术问答 |

---

## 二、平台与账号

| 项 | 内容 |
|----|------|
| **平台地址** | `gcsis.dasctf.com` |
| 账号 | 中文姓名 + 手机号后四位（如张三1234）或手机号 |
| 密码 | `Das#身份证后四位`（末位 X 大写，如 `Das#123X`） |
| 接入凭证 | 平台登录后「运行环境」处获取团队 **accesskey** |
| 文档中心 | 平台内「文档中心」可导出【API接入说明】+【大模型网关接入】markdown |

⚠️ `DasCTFPlatform` 默认 endpoints 是猜的（`/api/challenges` 等），真实路径以平台文档为准，测试赛当天拿到后覆盖 `endpoints` 参数。

---

## 三、授权 API 端点白名单（违规即取消资格）

**初赛 Agent 只能调用以下端点**（手册第三节，平台做流量审计）：

### DeepSeek（主用，性价比最高）
- `https://api.deepseek.com/chat/completions` ✅ 项目默认
- `https://api.deepseek.com/v1/chat/completions`
- `https://api.deepseek.com/responses`
- `https://api.deepseek.com/anthropic/v1/messages`

### 阿里云 Qwen 百炼（备选，新用户免费 1 亿+ tokens）
- `https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions` ✅ 项目默认
- `https://dashscope.aliyuncs.com/compatible-mode/v1/responses`
- `https://dashscope.aliyuncs.com/apps/anthropic/v1/messages`
- `https://coding.dashscope.aliyuncs.com/v1/chat/completions`
- `https://coding.dashscope.aliyuncs.com/apps/anthropic/v1/messages`

### 其他白名单（备用）
百度文心、字节豆包、智谱 GLM、腾讯 Hunyuan/TokenHub/LKEAP、月之暗面 Kimi、硅基流动、MiniMax、小米 MiMo、阶跃星辰、讯飞星火、商汤 SenseNova、百川智能——完整列表见 `llm/client.py` 的 `WHITELISTED_ENDPOINTS`。

**项目内验证**：`llm/client._check_whitelist()` 在每次 LLM 调用前校验；初赛部署设 `CTF_AGENT_ENFORCE_WHITELIST=1` 强制阻断违规端点。

---

## 四、竞赛规则（手册第七、八条）

### 4.1 Flag 提交
- 格式：`DASCTF{}` 或 `flag{}`，**提交时仅提交 {} 内内容**
- ⚠️ 手册与 API 文档自相矛盾（API 示例用 `"flag":"flag{example}"`）→ **以手册为准**，项目 `DasCTFPlatform.submit_flag` 已用 `_strip_flag_wrapper` 剥离外壳
- 每题最大提交 50 次，超限无法提交
- 禁止对 flag 爆破（违规取消成绩）

### 4.2 积分（递减模式）
- 初始 200 分，每多一人解出降 1%，最低 80%（160 分）
- 排名：分数高低，同分按时间先后
- **策略含义**：早解出分数高 → 多模型竞速 + 并发调度的速度优势直接转化为分数

### 4.3 Agent 接入
- 每队**仅允许一个 Agent 接入平台**
- subagent 是否算"Agent"官方未明确（选手群争议），保守起见项目用「1 主 1 监」架构（监督 Agent 不直接接平台，只在内部决策）
- 必须接入平台提供的大模型网关，所有通信经由白名单端点
- 所有网络请求被记录，事后审计

### 4.4 人工干预（⚠️ 红线）
- 官方选手群回复（8/17 18:03-18:50）：「**不鼓励人工引导**，希望选手主要关注 agent 自身的解题能力」
- 选手群分析：这是"事后裁定"策略——让你先比，赛后看日志判断是否违规
- **项目对策**：`InterventionCoordinator` 默认关闭，设 `CTF_AGENT_ALLOW_HUMAN=1` 才启用（开发/演示）；**初赛部署该变量必须未设置**

### 4.5 解题报告（必备）
- 比赛结束前必须在线提交解题报告
- 报告需与网络流量、平台日志吻合，否则取消获奖资格
- **项目缺口**：目前无报告生成功能 → todo（需要补：每题解题步骤、API 调用记录、最终 flag）

---

## 五、费用实战情报（选手群实测）

| 模型 | 实测成本 | 备注 |
|------|---------|------|
| deepseek-v4-flash | 4 题 ~25 元 | 最便宜，选手首选 |
| deepseek-v4-pro | 跑一次 tsec 全量 ~80 元 | 涨价后更贵 |
| qwen3.7-plus | 新用户免费 1 亿+ tokens | 性价比最高，零成本打完初赛 |
| glm5.3 | "有钱都上 glm" | 贵但强 |

**选手真实烧钱**：「今天烧了 270」「40 题最少 300 起步」「测试赛做了正赛没钱了」

**项目对策**：
1. **分级降级调度**（已有）：attempt 0-1 用 flash，2-3 才升级 pro
2. **预算熔断**（已有）：单题 80000 tokens / 全局 800000 tokens 硬停
3. **多模型竞速慎用**：会 double 成本 → 初赛只在难题用，简单题直接 DeepSeek 单跑
4. **优先 Qwen 免费额度**：初赛首选 `CTF_AGENT_LLM_PROVIDER=qwen`，免费打完整场

---

## 六、技术情报（选手群实战）

### 6.1 平台坑
- 附件下载常失败（选手吐槽"密码题附件下不来"）→ 项目 `build_platform_solver` 已做下载重试 + 失败不阻塞
- 百炼 workspaceID 添加不进平台 → 需用「原始 url」而非「专属 url」
- 网关 URL 支持 `/v1` 和 `/v1/chat/completions` 两种格式
- 主办方会"更新一批白名单" → 关注群公告

### 6.2 Agent 架构前沿讨论
- **树状 agent 结构**：每个会话是分支，避免上下文爆炸
- **多 Agent 协作**：主 Agent 调度子 Agent，分工解题
- **分布式部署**：Agent 跑在不同服务器上，规避"一个 IP"限制
- **反检测争议**："中间转一层 ds 的 flash，只做通信和返回，你怎么查"——属灰色地带，本项目不走这条路

### 6.3 选手能力分布
- Top 选手：有腾讯比赛经验（"脱胎于腾讯"）、打包 6 个版本镜像、用 tsecbench 测 agent
- 普通选手：费用焦虑严重，"穷逼大学生"是高频自嘲
- 灰色产业：疑似非大陆账号入群、私信诈骗、闲鱼买 flag
- AI 小号：沸羊羊/懒羊羊/奶龙等疑似 AI 入群观察

---

## 七、初赛作战 checklist

### 7.1 赛前（8/19-8/20）
- [x] 测试赛 8/19 17:00 前用真实平台跑通全流程（拉题→解题→提交）——7/7 全解出 800 分
- [x] 拿到 `DASCTF_BASE_URL`（pro.dasctf.com）+ `CTF_AGENT_PLATFORM_TOKEN`（40 位 accesskey）
- [x] 验证 `DasCTFPlatform.endpoints` 与官方文档一致（/slab-match/api/v1/agent/... 真实路径）
- [x] 解题报告生成功能开发（report/generator.py，mock 验证 848 字符）
- [x] 全流程彩排（8/20 mock 平台：拉题→竞速解题→提交→报告全链路通）
- [x] 降级预案：免费源竞速（baidu=千帆 ernie-3.5 / mimo / glm 备用）+ 注册表回退 + provider 模型隔离

**8/20 外部锐评整改闭环（证据核实见 solutions/锐评证据核实报告.md）**：
- ✅ 评测污染 __direct_extract__ 已禁用（d777dde）
- ✅ main_agent 1284→727 行拆解（cf88ff4）
- ✅ 文档瘦身（根目录 md 0 个、_xihu 已清）
- ✅ 冒烟测试套件 tests/（verify 三态门 + scheduler 三态熔断，27b5dc5）
- ✅ 止损规则完整：死循环 redirect + 连续失败2次升级 + 12步无进展 give_up + 空转检测
- ✅ 有效 API key 零泄漏（git 全历史核实）
- ✅ 竞速池 16 模型矩阵（8 provider 白名单内可用）
- ✅ 全量语法 187 文件通过 + 测试全绿

**8/20 彩排发现并修复的 3 个 bug**（初赛前清零）：
1. config.resolve_api_key 注册表回退（setx 后新进程读不到环境变量的坑）
2. llm/client provider 模型隔离（全局 LIGHT_MODEL 污染 baidu/mimo 端点 401）
3. main_agent flag_pattern 裸访问（ChallengeInfo 无此属性 → 主循环异常）
4. mock 平台路由更新为新版 endpoints（测试债）

### 7.2 初赛当天（8/21 14:00-17:00）
- [ ] 13:30 前启动 Agent，确认平台连通
- [ ] 14:00 开赛后 `--mode platform --interval 30` 持续轮询拉题
- [ ] 优先解能解的题（递减积分，早解出分数高）
- [ ] 监控 Web 看板解出率，但不主动注入提示（合规）
- [ ] 16:30 前完成解题报告提交（避免临时慌乱）
- [ ] 17:00 比赛结束前确认所有 flag 已提交

### 7.3 红线（违规即取消资格）
- ❌ 调用白名单外的 API 端点
- ❌ 人工引导解题方向（流量审计可见）
- ❌ 对 flag 爆破
- ❌ 与他人通信互动
- ❌ 用多个 Agent 接入平台
- ❌ 未提交解题报告 / 报告与日志不吻合

---

## 八、参考信息

- **平台地址**：`gcsis.dasctf.com`
- **选手群**：838552505（第三届，159 人，安恒运营维护）
- **主办**：安恒信息，阿里云 AI 支持
- **奖金池**：超 30 万（一等奖 1 / 二等奖 2 / 三等奖 3）
- **隐藏价值**：安恒在群内招 27 届实习生（温州），留群 = 进人才池

---

*本文件为初赛作战总参考，由参赛手册 + 选手群 1914 条消息精炼整理。*
*维护：每次官方公告更新后同步修订本文件。*

---

## 九、测试赛实战成果（8/19 10:30 更新）

### 9.1 成绩：🎉 7/7 全解出，800 分，排名 75

| 题 | 题型 | 解法 | flag |
|---|---|---|---|
| 10661 web-unserialize | WEB | www.zip 源码 POP 链 | 58266130425589704012625682808218 |
| 10663 解压缩 | MISC | 38 层 zip 文件名链 base32 | 9ce14a96-d148-44fe-ac3f-2307899a18f1 |
| 10696 TheoremPlus | CRYPTO | e=|2-π| + Fermat 分解 | Ot2N63D_n8L6kJt_f40V61m_zS1O8L7 |
| 10678 easy_uaf | PWN | UAF→复用chunk写here后门→print_score触发 | 78721193890431455923439319316326 |
| 10680 Fate | WEB | CC6+Nashorn 反射读 FLAG 字段 | Unl1mitted_Blade_Work |
| 10664 UploadKing | WEB | XXE SVG 读 /flag | 35787700367039558126436266564902 |
| 10662 shopping | PWN | tcache poisoning → free_hook=system | 50109837530035490833700696079246 |

### 9.2 初赛作战命令（8/21）

```bash
# 一键开跑（拉题→解题→提交→赛后自动生成报告）
cd E:/Program/西湖论剑/ctf_agent
setx CTF_AGENT_PLATFORM_TOKEN "<accesskey>"
python scripts/_race_start.py --forever

# 或手动：--once 单轮 / --probe 探测
# 单题：python scripts/_solve_platform_challenge.py --id <题号>
```

### 9.3 测试赛验证的合规要点
- ✅ 认证头 X-Agent-AccessKey + 浏览器 UA（WAF 拦 curl）
- ✅ flag 提交剥离外壳（{} 内内容）
- ✅ 白名单端点强制（CTF_AGENT_ENFORCE_WHITELIST=1）
- ✅ 解题报告生成器（report/generator.py，赛后自动生成）
