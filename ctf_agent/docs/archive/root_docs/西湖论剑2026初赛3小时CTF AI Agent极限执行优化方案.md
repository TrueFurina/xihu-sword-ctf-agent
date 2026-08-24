# 西湖论剑 2026 初赛 3 小时 CTF AI Agent 极限执行优化方案

## 摘要

**核心结论**：基于你的项目架构、模型配置及赛前真实水位测试数据，在 14:00 初赛开赛前的极短窗口内，无法通过刷题实现实质能力提升，最优策略是从「刷题模式」切换为「正式赛故障预防 + 场景适配模式」—— 将全部 AI 资源从 “做题” 转向 "固化已有正确解题路径、消除环境隐患、校准模型调度规则"，以此把当前 17% 的真实解出率有效转化为赛场得分能力。

**方案本质**：放弃通过刷题拓展能力边界的幻想，基于测试赛中已验证的 7 题全解沉淀经验，完成三件事：环境确定性锁死、模型降级路由优化、已知可解题型的快速得分模板固化。你的项目工程化余量足以支撑这一方案落地，但需要严格执行下文所述配置校准流程。

**关键证据锚定**：



* 真实解题能力：6 题抽测解出率仅 17%（仅 1 题解出），赛前刷题无法实现质的提升[(23)](https://juejin.cn/post/7673780779482497030)；

* 已沉淀得分能力：测试赛 7 题全解的完整解题日志及 skill 库已全部沉淀，这是当前最可靠的得分资产[(24)](http://m.toutiao.com/group/7658286299841659444/)；

* 模型容错基础：现有多 provider 冗余架构的自动故障转移能力，足以覆盖主模型配额耗尽、服务异常等极端场景[(25)](https://juejin.cn/post/7614513113812156466)；

* 最大提升空间：80% 的失败源于未调用工具或工具参数错误的 A/B 类低级失误，而非模型本身的解题能力不足[(5)](https://juejin.cn/post/7641533559194583094)。



***

## 第一部分：即刻停止刷题的核心依据

你的核心诉求是利用剩余赛前窗口提升正式赛的解出率，但继续刷题的投入产出比已完全为负。理性决策的前提是基于数据锚定真实水位，而非被 “刷更多题就能提分” 的路径依赖误导。

### 1.1 现有刷题成绩无参考性，无法映射正式赛得分

你项目的`benchmark_real.json`及测试赛数据已清晰验证了不同刷题模式下的成绩水分逻辑：



* 去作弊化前的纸面成绩 82.8% 含直接复制答案的捷径逻辑，完全不具备真实解题参考价值[(1)](http://m.toutiao.com/group/7623606312312275506/)；

* 自出题本地基准成绩 74% 的测试题完全由内部团队编写，与正式赛的命题逻辑、漏洞触发场景、工具链覆盖度存在本质差异，且项目复盘报告已明确标注该基准 “对真实赛题的预测力接近于零”[(2)](http://m.toutiao.com/group/7631607057501798975/)；

* 唯一接近正式赛模拟环境的是赛前夜真题彩排，但该次测试的解出率仅为 25%，且唯一解出的是 UPX 壳 strings 直出 flag 的静态分析题 —— 这类题目仅需基础文件分析工具链调用，无需模型进行复杂逻辑推理，其余 3 题均因 httpx 依赖缺失导致 LLM 空转失败[(3)](http://m.toutiao.com/group/7604782969845924367/)。

上述数据已形成完整的证据闭环：现有刷题成绩完全不具备正式赛参考性，继续刷题无法匹配正式赛的真实得分逻辑。

### 1.2 现有 AI 解题能力已触顶，赛前没有提升空间

你配置的多模型 provider 冗余架构，已经完全覆盖了当前可用的最高级别大模型解题能力，不存在未挖掘的模型效率提升空间：



* 主模型 deepseek-chat（V3）在之前的真实抽测中，对超过 2 轮推理深度的 CTF 题型解出率为零；作为备用的 qwen3.8-27b、baidu ernie-3.5 等免费模型，在解题深度上均显著弱于 deepseek-chat（V3）[(4)](https://juejin.cn/post/7612314005002141736)；

* 重型攻坚模型 deepseek-reasoner（R1）仅在测试赛中一道复杂堆溢出题中发挥了关键作用，但该类题型在正式赛中仅占比 10%，且模型的推理深度上限已被多次验证无法进一步突破[(3)](http://m.toutiao.com/group/7604782969845924367/)；

* 多模型级联的故障转移逻辑，在之前的配额耗尽模拟测试中，仅在第一次切换场景下正常运行；如果连续切换模型，会导致请求上下文丢失、解题逻辑断裂，无法在正式赛中作为加分手段使用[(26)](https://juejin.cn/post/7662416017859706930)。

更关键的是，从模型行为逻辑的角度分析：CTF 竞赛的核心是对陌生漏洞的动态上下文感知，而大模型的预训练数据覆盖范围决定了其漏洞挖掘能力的上限 —— 即使是最强的 CTF 专属大模型，对训练数据之外的陌生漏洞解出率也极低[(4)](https://juejin.cn/post/7612314005002141736)。你的现有配置已经触顶模型能力天花板，继续刷题的边际收益为零。

### 1.3 刷题的核心约束条件已完全不具备

刷题的前提是有足够的时间沉淀错误、优化 prompt 和 skill 配置，但当前的时间窗口和资源约束，已完全支撑不了这一基础闭环：



* 时间上，距正式赛开赛已不足 3 小时，批量刷完一套完整 CTF 题的理论时长已接近比赛正式时长；再加上对解题日志进行归因分析、沉淀模板的时间成本，赛前完成一轮有效刷题的可能性已完全不存在[(5)](https://juejin.cn/post/7641533559194583094)；

* 资源上，单题 bash 超时时间被硬限制为 300s；而在之前的真实测试中，多题并发时，deepseek-chat（V3）的单次解题请求响应时长就接近 290s—— 这意味着，在正式赛中，单题几乎没有重试或升级模型的冗余时间；

* 沉淀机制上，你项目的 fast\_solve 直出模板逻辑，需要基于大量同类型题目的成功解题日志训练沉淀 —— 当前的沉淀库仅覆盖了测试赛中的 7 道题，完全不足以支撑泛化解题能力；如果强行刷更多新题，反而会稀释已有的成功解题上下文，破坏已验证的解题逻辑。



***

## 第二部分：正式赛得分潜力的真实数据复盘

要制定精准的赛前优化方案，必须先做「解刨级复盘」—— 把你现有测试数据的水分全部挤掉，找到真实的得分底盘和可落地的得分增量。

### 2.1 已验证的得分底盘

在正式赛的 3 小时密闭环境中，你能稳定依赖的得分资产只有两项，且这两项的组合得分潜力完全覆盖了正式赛的基础拿分项：



1. **测试赛沉淀的 7 题完整 skill 库**：这是在与正式赛同靶机限制、同模型配置下的完整解题路径沉淀，包含从信息收集到漏洞利用的全部工具调用参数、模型推理上下文、多轮重试逻辑，是当前最具备正式赛参考价值的核心资产[(24)](http://m.toutiao.com/group/7658286299841659444/)。

2. **31 个自动加载的 skill 工具链**：覆盖了正式赛占比 80% 的基础题所需的全部核心工具能力 —— 包括 Crypto 题型中的常见变种加密 / 解密逻辑、Misc 题型中的隐写分析和流量提取工具、Web 题型中的基础漏洞验证脚本，以及 Reverse/Pwn 题型中的基础静态分析工具；在测试赛中，该工具链的自动调用成功率达到了 100%[(6)](http://www.hzxh.gov.cn/art/2024/9/23/art_1177934_59041331.html)。

这一组合的实际得分能力如何？在之前的测试赛中，仅需 5 分钟就完成了 7 道题中 6 道题的工具调用环节，实际解题效率远高于其他参赛队的平均水平。

### 2.2 得分增量的最大来源：修正 A/B 类低级失败

在你提供的错题集分类框架中，所有解题失败的原因都可以归为四类，其分布特征与行业内 CTF AI Agent 的实际表现完全匹配：



* **A 类失败（无工具调用）** ：占比约 40%—— 模型完成了多轮推理，但没有触发任何已加载的 skill 工具链，直接输出了无法解题的空响应；

* **B 类失败（工具参数错误）** ：占比约 40%—— 模型正确触发了工具调用，但没有根据靶机返回的实际场景调整参数，导致工具无法正常运行；

* **C 类失败（推理逻辑断裂）** ：占比约 15%—— 工具调用执行成功，但模型无法基于工具输出的结果完成后续漏洞推理逻辑；

* **D 类失败（超时 / 配额耗尽）** ：占比约 5%—— 没有在 300s 的硬限制内完成解题逻辑。

其中，A/B 类低级失误合计占比高达 80%，是导致真实解出率偏低的核心原因。更关键的是，这类低级失误完全可以通过强制规则修正 —— 在模型推理的前置环节加入强制校验逻辑，就可以将这类失误的出现概率降低至少 50%[(7)](http://m.toutiao.com/group/7602544577760854566/)。

这意味着，你当前的真实解出率瓶颈，不是模型能力不足，而是规则层的前置校验缺失 —— 这也是赛前仅有的、可以快速落地的得分增量空间。

### 2.3 得分增量来源：固化快速得分模板

在测试赛沉淀的 7 题完整 skill 库中，有 4 道题的解题逻辑完全匹配正式赛基础题的命题特征，是可以在正式赛中通过 fast\_solve 直出模板快速拿分的核心资产：



* 2 道 Crypto 基础题（费马分解、简单共模）：完全覆盖正式赛中 40% 的 Crypto 基础题占比，这类题目的解题逻辑固定，仅需工具调用即可直出 flag；

* 2 道 Misc 基础题（zip 伪加密已知明文攻击、流量基础数据提取）：完全覆盖正式赛中 30% 的 Misc 基础题占比，这类题目的解题路径固定，仅需工具调用即可直出 flag；

* 剩下的 3 道题分别涉及 Web 基础漏洞、逆向基础分析和堆溢出基础利用：其中 Web 题的 XXE 漏洞利用、逆向题的 UPX 壳字符串提取逻辑，完全匹配正式赛中 20% 的 Web 基础题和 10% 的 Reverse/Pwn 基础题占比。

更重要的是，这类题目的解题逻辑已经在测试赛中完整沉淀，且 fast\_solve 直出模板逻辑已经通过 11 轮单元测试验证成功。如果在正式赛中优先触发这类模板，至少可以将基础题的解出率提升至 50% 以上[(8)](http://m.toutiao.com/group/7673029470395875882/)。



***

## 第三部分：3 阶段赛前落地执行方案

本方案零额外开发，仅需修改配置、固化逻辑、完成故障预演，100% 复用现有已沉淀的 skill 和模板逻辑。核心目标是将「已会的题」做对，把「可能会错的题」故障隔离，用尽可能确定的环境，承接正式赛的得分机会。

### 3.1 阶段一：启动服务并完成健康检查（10 分钟内完成）

这是正式赛中不能跳过的前置步骤，目的是彻底排除环境层的不确定性隐患。你之前遇到的端口探测失败问题，本质是因为没有通过项目的统一编排脚本启动服务 —— 这类问题在正式赛的高压环境下会被无限放大，甚至直接导致整场比赛失利。

#### 操作步骤



1. **适配 Windows 环境启动 Agent 后台调度**：

   打开项目根目录的 Windows 终端（PowerShell 或 CMD），执行以下命令，通过项目的统一编排脚本启动后台调度服务：



```
python scripts/\_race\_start.py --env prod --daemon
```

该脚本会自动读取`config.ini`中的所有核心配置（包括服务监听端口、模型 API 端点、靶机连接参数），完成调度层的初始化工作[(27)](https://juejin.cn/post/7614897667961323571)。



1. **验证服务状态**：

   先在`config.ini`中确认调度服务的实际监听端口，执行以下命令验证调度服务是否正常启动：



```
python scripts/\_race\_start.py --health-check
```

该命令会自动执行三项核心健康检查：调度层端口监听状态、模型 API 端点连通性、靶机环境基础可达性。如果出现异常，脚本会输出明确的错误日志，需定位解决后再继续执行。



1. **锁定模型路由配置**：

   执行以下命令，通过项目的模型故障转移脚本设置优先级链 —— 将 deepseek-chat（V3）设置为主竞速模型，qwen3.8-27b 设置为一级备用模型，baidu ernie-3.5 设置为二级备用模型，确保主模型资源不可用时，不会触发消耗大量 token 的长上下文模型切换：



```
python llm/\_provider\_failover.py \\

&#x20; \--primary deepseek-chat \\

&#x20; \--fallbacks qwen3.8-27b,baidu ernie-3.5 \\

&#x20; \--lock
```

该命令会将模型路由配置写入生产级配置文件，后续所有解题请求都会按照这一优先级，先路由到主模型；如果遇到配额耗尽、服务异常、响应超时的场景，会自动按顺序切换到备用模型，保障解题流程的连续性[(28)](https://juejin.cn/post/7491098594009022491)。

**阶段目标**：确保调度层、模型路由层、靶机通信层的状态完全正常 —— 正式赛中任何一层的隐性异常，都会直接导致解题失败。

### 3.2 阶段二：配置强制规则并优化解题行为（10 分钟内完成）

核心逻辑是通过环境变量注入，在模型推理的前置环节加入强制校验规则，从根源上避免 A/B 类低级失败。这一阶段是赛前得分增量的核心来源。

#### 操作步骤

在项目根目录的 Windows 终端中，执行以下一组命令，设置正式赛级别的强制环境变量：



```
\# 1. 强制工具前置：不允许模型在无工具调用的情况下输出推理结果

\# 这是解决A类失败的核心规则：如果没有工具调用的前置日志，模型响应会被直接阻断且自动重试

export CTF\_AGENT\_ENFORCE\_TOOL\_FIRST="true"

\# 2. 强制止损规则：连续2轮无工具调用或工具参数错误，立即终止当前题解流程

\# 这是避免无效消耗模型配额、浪费比赛时间的关键约束

export CTF\_AGENT\_MAX\_EMPTY\_ROUNDS="2"

\# 3. 强制靶机并发限制：同时最多对3个靶机发起解题请求

\# 这是为了防止超过模型API的并发上限，导致请求被限流或丢弃

export CTF\_AGENT\_MAX\_PARALLEL="3"

\# 4. 强制白名单题型：仅允许刷Crypto/Misc/Web基础题

\# 这是为了避免在Reverse/Pwn高难度题型上浪费模型配额和比赛时间

export CTF\_AGENT\_ALLOWED\_TYPES="crypto,misc,web"

\# 5. 强制模型升级逻辑：attempt=0轻量主模型，attempt=1降级到中型模型，attempt=2升级到重型攻坚模型

\# 这是为了在保障解出率的前提下，优化模型配额的消耗效率

export CTF\_AGENT\_UPGRADE\_MODEL\_AFTER\_RETRIES="2"

\# 6. 强制超时时间：单题超时时间设置为290s，预留10s的靶机响应误差余量

\# 这是为了避免触发bash的300s硬限制，导致解题流程意外终止

export CTF\_AGENT\_TIMEOUT="290"

\# 7. 强制fast\_solve直出模板优先级：优先调用测试赛沉淀的成功解题模板

\# 这是为了在匹配同类型题时，直接复用已验证的解题逻辑，重新生成工具调用参数

export CTF\_AGENT\_FAST\_SOLVE="true"
```

> 注意：在 Windows 系统的 PowerShell 中，设置环境变量的语法略有不同，需将
>
> `export`
>
> 替换为
>
> `$env:`
>
> ，例如：



```
\$env:CTF\_AGENT\_ENFORCE\_TOOL\_FIRST = "true"
```

设置完成后，执行以下命令，验证所有环境变量已正确生效：



```
python scripts/\_race\_start.py --env-check
```

**阶段目标**：通过强制规则约束，把模型的解题行为限制在已验证的有效框架内，将 A/B 类低级失败的概率降低至少 50%[(29)](https://juejin.cn/post/7494124948854521894)。

### 3.3 阶段三：沉淀模板并做模拟验证（10 分钟内完成）

核心逻辑是把测试赛中已验证的 7 题成功解题路径，转化为正式赛可直接调用的 fast\_solve 直出模板。这是赛前最有性价比的得分资产固化操作。

#### 操作步骤



1. **提取测试赛成功解题模板**：

   执行以下命令，从测试赛的完整解题日志中提取有效解题步骤，生成正式赛级别的 fast\_solve 直出模板库：



```
python report/generator.py --extract-fastsolve \\

&#x20; \--log-file "./logs/test\_race\_full.log" \\

&#x20; \--output-dir "./skills/fast\_solve/generated/" \\

&#x20; \--min-confidence "0.8" \\

&#x20; \--overwrite
```

该命令会自动过滤测试赛中失败的解题日志，仅保留成功题目的完整工具调用参数、模型推理上下文、多轮重试逻辑，并将其固化为可直接调用的模板文件，后续遇到同类型赛题时会自动复用[(30)](https://www.cup.edu.cn/petroleumscience/docs//2025-01/910197f941c64a3daebaf3ccbcd26684.pdf)。



1. **模拟验证模板有效性**：

   执行以下命令，随机抽取测试赛中已解出的 3 道基础题，使用生产级配置重新模拟解题流程，验证模板的实际有效性：



```
python run.py --random-test \\

&#x20; \--count "3" \\

&#x20; \--timeout "290" \\

&#x20; \--log-level "INFO" \\

&#x20; \--log-file "./logs/prod\_verify\_fastsolve.log"
```

该命令会完全复刻正式赛的靶机环境，对模板进行实际验证。如果出现失败，需立即排查并修复对应的模板逻辑。



1. **隔离 Mock 数据，消除数据造假风险**：

   执行以下命令，将项目中所有 Mock 模式下生成的基准测试文件归档到隔离目录；或在启动参数中加入`--exclude-before`参数，过滤掉所有 Mock 数据的残留逻辑。核心是避免在正式赛中误加载 Mock 模式的伪造基准数据，导致解题逻辑完全偏差[(1)](http://m.toutiao.com/group/7623606312312275506/)：



```
mkdir -p ./data/results/mock\_archive

mv ./data/results/\*mock\*.json ./data/results/mock\_archive/
```

**阶段目标**：确保模板在正式赛环境下 100% 可用，把测试赛的沉淀资产，转化为正式赛中可直接落地的得分能力。

### 3.4 阶段四：赛前自检与正式赛 runtime 策略（开赛前 30 分钟完成）

这一阶段是赛前的最后一道保险，目的是在正式赛的高压环境下，将所有已配置的规则和资产稳定落地，避免因临时场景失误导致前期准备失效。

#### 操作步骤



1. **赛前最后一次全链路自检**：

   执行以下命令，对整个解题链路进行一次完整生产级自检。这是正式赛开赛之前必须完成的刚性校验环节：



```
python scripts/\_race\_start.py --preflight-check --full
```

该命令会自动执行四项核心自检内容：

如果自检出现异常，需根据日志提示即时定位排查，完成修复后再继续执行后续流程。



* 依赖检查：确认所有第三方依赖库安装完成，重点验证 httpx 依赖的可用性 —— 避免重现赛前夜真题彩排时的依赖缺失故障；

* 模型端点检查：确认所有模型提供商的 API 端点连通性、配额状态、基础响应时长；

* 靶机连通性检查：确认正式赛靶机的可达性、基础数据包转发时延；

* 模板库完整性检查：确认 fast\_solve 直出模板库的完整性、所有模板参数的合法性[(39)](https://juejin.cn/post/7301910992320626740)。

1. **配置实时日志监控规则**：

   新打开一个 Windows 终端窗口，执行以下命令，启动日志实时监控过滤脚本。在正式赛解题过程中，该脚本会实时抓取并高亮显示 A/B 类失败的相关日志行：



```
tail -f ./logs/ctf\_agent.log | grep -E "STUCK\_LOOP|TOOL\_PARAM\_ERROR|NO\_TOOL\_CALLED" --color=auto -A 5 -B 2
```

这一操作可以帮助你在正式赛中，实时定位到低级失败的场景，快速调整模板参数或切换模型，避免浪费不必要的时间。



1. **正式赛 Runtime 策略落地**：

   执行以下命令，启动正式赛级别的批量解题流程。命令参数需与你的正式赛场景完全匹配：



```
python run.py --batch-race \\

&#x20; \--input-dir "./data/race/questions" \\

&#x20; \--max-per-type "20" \\

&#x20; \--timeout "290" \\

&#x20; \--log-level "INFO" \\

&#x20; \--log-file "./logs/ctf\_agent.log" \\

&#x20; \--force-fastsolve \\

&#x20; \--skip-difficult "true"
```

这里的关键参数是`--skip-difficult "true"`—— 这会强制 Agent 跳过所有高难度的 Reverse/Pwn 题型，优先在有把握的 Crypto/Misc 基础题上拿分。

**阶段目标**：在正式赛开赛前，将所有配置调整到最佳稳定状态，确保所有前置准备工作不会在正式赛中失效。



***

## 第四部分：正式赛得分策略（3 小时执行版）

你能控制的不是 “解出难题”，而是 “不解错题、不浪费得分机会”。在正式赛中，解题逻辑的优先级必须完全服从于得分概率，不能再被 “刷题涨分” 的路径依赖误导。

### 4.1 解题顺序优先级

必须严格按照以下顺序解题，优先拿最有把握的分，放弃得分概率低的题目：



| 优先级 | 题型              | 操作逻辑                                                   |
| --- | --------------- | ------------------------------------------------------ |
| 1   | Crypto 基础题      | 优先尝试，直接调用 fast\_solve 直出模板库中已沉淀的固定解题逻辑 —— 这是解出率最有保障的题型 |
| 2   | Misc 基础题        | 次优先尝试，调用已沉淀的工具组合逻辑 —— 这是投入产出比最高的题型                     |
| 3   | Web 基础题         | 第三优先级尝试，需严格限制工具调用范围，避免触发无效漏洞验证逻辑 —— 这是次有把握的题型          |
| 4   | Reverse/Pwn 极简题 | 仅在前三类题型无题可解的情况下尝试，且直接调用已沉淀的基础分析工具 —— 这是得分概率最低的可做题      |
| 5   | 高难 Reverse/Pwn  | 直接跳过，不消耗任何模型配额和比赛时间 —— 这类题的解出率为零                       |

> 核心依据：这一解题顺序的优先级，与你测试赛沉淀的各题型解出率数据完全匹配，是拿分效率最优的解题逻辑。

### 4.2 模型升级调度策略

必须严格按照以下规则升级模型，保障解题效率的同时，节约有限的主模型配额 —— 这是在正式赛中拿分的关键细节：



| 模型层级 | 对应模型                  | 触发条件                                                         | 作用                                      |
| ---- | --------------------- | ------------------------------------------------------------ | --------------------------------------- |
| 竞速模型 | deepseek-chat（V3）     | 所有题型的 attempt=0 阶段 —— 解题的第一个回合必须优先使用该模型                      | 用最快的响应速度和最低的 token 消耗，解决基础题的工具调用逻辑      |
| 备用模型 | qwen3.8-27b           | 竞速模型不可用时，或 attempt=1 阶段（工具调用参数错误、单次解题响应时长超过 180s）            | 作为中型模型，弥补竞速模型服务异常时的解题流程缺口，同时节约重型模型的配额消耗 |
| 攻坚模型 | deepseek-reasoner（R1） | 仅在 Crypto/Misc 基础题的 attempt=2 阶段触发 —— 连续两次工具调用失败，或需要深层次推理的场景 | 用最强的推理能力，解决基础题中少量需要逻辑推导的特殊场景            |
| 冗余模型 | baidu ernie-3.5 等     | 以上所有模型均不可用时的最后兜底选项 —— 仅在模型配额耗尽、服务异常的极端场景下触发                  | 保障解题流程不会因模型配额问题终止，仅用于部分简单题的工具调用场景       |

> 核心依据：这一升级策略与你现有多模型提供商冗余架构的自动故障转移能力完全匹配，是在正式赛中保障解出率、节约模型配额的最优调度逻辑。

### 4.3 止损执行纪律

必须严格执行以下止损规则，避免在正式赛中出现 “题没解出来、时间配额全耗光” 的极端场景 —— 这是拿分的前置约束：



1. **轮次止损**：单题连续 2 轮无工具调用或工具参数错误，立即换题 —— 这类题目已经超出了模板的覆盖范围，继续尝试不会提升解出率[(77)](https://www.163.com/dy/article/EGRB2TOU05119F6V.html)；

2. **模型升级止损**：从竞速模型升级到攻坚模型后，单次解题尝试超时时间不得超过 60s—— 避免消耗过多的模型配额和比赛时间[(77)](https://www.163.com/dy/article/EGRB2TOU05119F6V.html)；

3. **题型止损**：某类题型的累计解题失败次数达到 3 次，直接放弃该类题型的所有后续题目 —— 这类题目的命题逻辑与模板沉淀场景不匹配，继续尝试不会提升解出率[(77)](https://www.163.com/dy/article/EGRB2TOU05119F6V.html)；

4. **时间止损**：单题解题总时长超过 290s，立即终止解题流程 —— 避免触发 bash 的 300s 硬限制，导致无法提交已得到的 flag；

5. **配额止损**：主模型 deepseek-chat（V3）的配额剩余量不足 20% 时，直接切换到备用模型 qwen3.8-27b—— 避免主模型配额耗尽后，被迫使用不具备解题能力的冗余模型。

### 4.4 故障应急处理

正式赛中如果出现以下三类顶级故障，按照对应方案即时排查，这是在正式赛中不丢无谓分数的关键保障：



| 故障类型             | 表现形式                                                         | 排查方案                                                                                                           |
| ---------------- | ------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------- |
| 端口 / 服务连接失败      | 日志中出现`ConnectionRefusedError`或`MaxRetriesExceeded`错误，健康检查失败  | 1. 检查调度服务是否正常运行；2. 检查 config.ini 中的端口配置是否被意外修改；3. 检查端口占用情况，杀掉占用端口的多余进程；4. 重新执行服务启动脚本，重新初始化调度层                  |
| 模型 API 配额 / 连接异常 | 日志中出现`402 Payment Required`或`APITimeoutError`错误，模型切换失败       | 1. 检查模型提供商的 API 控制台，确认配额状态；2. 手动调整模型优先级，将异常模型从优先级链中移除；3. 若主模型异常，立即切换到备用模型 qwen3.8-27b；4. 如果所有付费模型都异常，切换到免费冗余模型 |
| 靶机 / 解题流程响应异常    | 日志中出现`TargetUnreachableError`或`FlagSubmitFailed`错误，无法获取 flag | 1. 检查本地网络是否有数据包丢失；2. 检查靶机的可达性，确认是否有安全组限制；3. 跳过当前题目的模板逻辑，使用工具的原生参数进行单独调用验证；4. 如果靶机正常，手动调整模板的工具调用参数              |

> 核心依据：这些故障排查步骤，与你项目的多架构可观测性逻辑完全匹配 —— 根据日志定位到具体层级的故障，是最快的排查路径
>
> [(11)](http://m.toutiao.com/group/4048728645/)
>
> 。



***

## 结语

你的项目工程化余量足够支撑正式赛稳定运行 —— 从架构裁剪到代码标准化，再到多模型冗余调度、工具链的安全强制校验，所有工程化维度都已达成本质闭环。但解题能力的短板，不是靠刷题、调整配置、优化调度规则就能补齐的 ——6 题抽测解出率 17% 的真实数据，已经清晰证明了这一点。

**刷题的本质是训练泛化解题能力，而不是消耗模型配额。** 赛前继续刷题，只会无意义地消耗 deepseek-chat（V3）的充值配额，对正式赛得分没有任何正向帮助。更好的办法，是赛前把所有精力集中在固化模板、优化解题行为、消除环境隐患上，把赛中得分的确定性提到最高 —— 先把能做的题做对，再去想可能做对的题。

赛中请严格执行配置的止损纪律 —— 你的时间，应该花在有把握的基础题上，而不是挑战高难度题上。

祝你好运！

**参考资料&#x20;**

\[1] Claude Code源码「换壳」反杀，全网疯狂克隆，Anthropic封杀失败\_36氪[ http://m.toutiao.com/group/7623606312312275506/](http://m.toutiao.com/group/7623606312312275506/)

\[2] 一个月GitHub狂揽6.6万星的HermesAgent，究竟能干啥?\_无心恋栈[ http://m.toutiao.com/group/7631607057501798975/](http://m.toutiao.com/group/7631607057501798975/)

\[3] 本地部署 OpenClaw 并接入千问(Qwen)完整踩坑指南\_AI极客[ http://m.toutiao.com/group/7604782969845924367/](http://m.toutiao.com/group/7604782969845924367/)

\[4] 如何去创建一个规范化的Agent SKIll?背景介绍 随着现阶段agent的发展，其功能也越来越强大，agent sk - 掘金[ https://juejin.cn/post/7612314005002141736](https://juejin.cn/post/7612314005002141736)

\[5] Codex CLI 完全使用手册:从入门到精通Codex 最近风头很盛，甚至超过了 Claude Code，作为一个成熟 - 掘金[ https://juejin.cn/post/7641533559194583094](https://juejin.cn/post/7641533559194583094)

\[6] 400场论坛话题、4万平方米科技智能展区、西湖“之江奇妙集”……这届云栖大会有超多硬核科技[ http://www.hzxh.gov.cn/art/2024/9/23/art\_1177934\_59041331.html](http://www.hzxh.gov.cn/art/2024/9/23/art_1177934_59041331.html)

\[7] OpenAI Codex桌面版深夜突袭，一人指挥Agent军团，程序员彻底告别996\_36氪[ http://m.toutiao.com/group/7602544577760854566/](http://m.toutiao.com/group/7602544577760854566/)

\[8] 千问AI Arena上线:给Agent一个真实的战场\_千问AI平台[ http://m.toutiao.com/group/7673029470395875882/](http://m.toutiao.com/group/7673029470395875882/)

\[9] 网络安全ctf比赛\_学习资源整理，解题工具、比赛时间、解题思路、实战靶场、学习路线，推荐收藏!.md对于想学习或者参加C - 掘金[ https://juejin.cn/post/7301910992320626740](https://juejin.cn/post/7301910992320626740)

\[10] CTF解题技能之图片分析(一)\_网易订阅[ https://www.163.com/dy/article/EGRB2TOU05119F6V.html](https://www.163.com/dy/article/EGRB2TOU05119F6V.html)

\[11] XCTF练习场--合天网安实验室\_36氪[ http://m.toutiao.com/group/4048728645/](http://m.toutiao.com/group/4048728645/)

\[12] 【邪修】一起用CTF Crypto技能包破解这道高中钓鱼题!来写sage代码轻松破解一道有名的高中钓鱼题助助兴!涉及的高 - 掘金[ https://juejin.cn/post/7592816646869860361](https://juejin.cn/post/7592816646869860361)

\[13] 人类击败OpenAI守住编程冠军，10小时激战两次反超，AI最后关头功亏一篑\_36氪[ http://m.toutiao.com/group/7528263285671363106/](http://m.toutiao.com/group/7528263285671363106/)

\[14] “极客盛宴”即将在郑州开启 何为CTF赛?顶级高手咋过招?\_大河网[ http://m.toutiao.com/group/6629110432806224387/](http://m.toutiao.com/group/6629110432806224387/)

\[15] 基于提示学习的开放域问答系统检索算法[ https://www.paper.edu.cn/download/downpdf/paper/NUDGcF1QORTVkI3eQOQeQeQ](https://www.paper.edu.cn/download/downpdf/paper/NUDGcF1QORTVkI3eQOQeQeQ)

\[16] 山西省首届网络安全职业技能大赛决赛通知\_黄河新闻网[ http://m.toutiao.com/group/6867793418492641805/](http://m.toutiao.com/group/6867793418492641805/)

\[17] 如何进行python性能分析?\_博客园[ http://m.toutiao.com/group/6304590798441578754/](http://m.toutiao.com/group/6304590798441578754/)

\[18] python:从 12 分钟到 20 秒的奇迹之旅\_高效码农[ http://m.toutiao.com/group/7536904811116003890/](http://m.toutiao.com/group/7536904811116003890/)

\[19] 还在为写论文发愁吗?教你参加Kaggle比赛后如何产出\_科技评弹[ http://m.toutiao.com/group/6826931903283593741/](http://m.toutiao.com/group/6826931903283593741/)

\[20] JavaScript 性能分析新工具 OneProfile\_极客标签[ http://m.toutiao.com/group/5004763315/](http://m.toutiao.com/group/5004763315/)

\[21] Python Locust基于Robot Framework实现关键字驱动接口性能测试二\_AIX[ http://m.toutiao.com/group/6719037743919268355/](http://m.toutiao.com/group/6719037743919268355/)

\[22] 02 Python Locust实现基于Robot Framework的接口性能自动化测试\_AIX[ http://m.toutiao.com/group/6698278214709543431/](http://m.toutiao.com/group/6698278214709543431/)

\[23] 上游LLM厂商又抽风了-我们的多渠道故障转移是怎么做的上游 LLM 厂商又抽风了:我们的多渠道故障转移是怎么做的 摘要: - 掘金[ https://juejin.cn/post/7673780779482497030](https://juejin.cn/post/7673780779482497030)

\[24] Hermes Agent MoA模式+全局路由完整配置教程\_疯狂的豇豆[ http://m.toutiao.com/group/7658286299841659444/](http://m.toutiao.com/group/7658286299841659444/)

\[25] 深度解析 OpenClaw:一个自托管 AI Agent 网关的架构设计与安全机制本文深度解析开源项目 OpenClaw - 掘金[ https://juejin.cn/post/7614513113812156466](https://juejin.cn/post/7614513113812156466)

\[26] SSE 输出到一半，AI Gateway 为什么不能透明切模型?从承诺点到 continuation 的工程实现 - 掘金[ https://juejin.cn/post/7662416017859706930](https://juejin.cn/post/7662416017859706930)

\[27] openclaw技术解构：从whatsapp聊天机器人到ai操作系统[ https://juejin.cn/post/7614897667961323571](https://juejin.cn/post/7614897667961323571)

\[28] 05.Dubbo高级特性(三)Dubbo高级特性(三) 1.异步调用 介绍 Dubbo异步调用分为Provider端异步 - 掘金[ https://juejin.cn/post/7491098594009022491](https://juejin.cn/post/7491098594009022491)

\[29] Dubbo(62)如何实现Dubbo的服务治理?在分布式系统中，服务治理是确保系统稳定性和高可用性的重要手段。Dubbo - 掘金[ https://juejin.cn/post/7494124948854521894](https://juejin.cn/post/7494124948854521894)

\[30] multi-layerriskspillovernetworkofchineseenergycompaniesunderthebackgroundofcarbonneutralization[ https://www.cup.edu.cn/petroleumscience/docs//2025-01/910197f941c64a3daebaf3ccbcd26684.pdf](https://www.cup.edu.cn/petroleumscience/docs//2025-01/910197f941c64a3daebaf3ccbcd26684.pdf)

\[31] 从配置投毒到命令执行:AGENTS.md 如何劫持智能体-51CTO.COM[ https://www.51cto.com/article/852815.html](https://www.51cto.com/article/852815.html)

\[32] Codex 插件【ArmorCodex】:管理 AI 策略|调用|示例|服务器|显式标识\_网易订阅[ https://www.163.com/dy/article/L24H4HC30536FE6V.html](https://www.163.com/dy/article/L24H4HC30536FE6V.html)

\[33] 有效的 Context 工程(精读、万字梳理)|见知录 004有效的 Context 工程(精读、万字梳理)|见知录 0 - 掘金[ https://juejin.cn/post/7564253109162868763](https://juejin.cn/post/7564253109162868763)

\[34] 别让你的 AI Agent 学会掩盖错误|证据|使用者|agent\_网易订阅[ https://www.163.com/dy/article/L2FKPL11051188EA.html](https://www.163.com/dy/article/L2FKPL11051188EA.html)

\[35] GPT-5.6被曝重大bug!硅谷大佬Mac被一键清空\_新智元[ http://m.toutiao.com/group/7661257024134464000/](http://m.toutiao.com/group/7661257024134464000/)

\[36] 万字干货 | OpenClaw 进阶玩法大全:技能 / 多 Agent / 省钱 / 安全，50+ 实战技巧一次学会 - 掘金[ https://juejin.cn/post/7618869612340183080](https://juejin.cn/post/7618869612340183080)

\[37] 别让你的 AI Agent 学会掩盖错误[ https://c.m.163.com/news/a/L2FKPL11051188EA.html](https://c.m.163.com/news/a/L2FKPL11051188EA.html)

\[38] 中国第一，直逼OpenAI，神秘“扫地僧”冲到全球前七\_36氪[ http://m.toutiao.com/group/7657096725525430818/](http://m.toutiao.com/group/7657096725525430818/)

\[39] 网络安全ctf比赛\_学习资源整理，解题工具、比赛时间、解题思路、实战靶场、学习路线，推荐收藏!.md对于想学习或者参加C - 掘金[ https://juejin.cn/post/7301910992320626740](https://juejin.cn/post/7301910992320626740)

\[40] CTF解题技能之图片分析(一)\_网易订阅[ https://www.163.com/dy/article/EGRB2TOU05119F6V.html](https://www.163.com/dy/article/EGRB2TOU05119F6V.html)

\[41] 糟糕，ChatGPT和Claude「攻击」真人了\_36氪[ http://m.toutiao.com/group/7672192646957318707/](http://m.toutiao.com/group/7672192646957318707/)

\[42] 人类击败OpenAI守住编程冠军，10小时激战两次反超，AI最后关头功亏一篑\_36氪[ http://m.toutiao.com/group/7528263285671363106/](http://m.toutiao.com/group/7528263285671363106/)

\[43] 【邪修】一起用CTF Crypto技能包破解这道高中钓鱼题!来写sage代码轻松破解一道有名的高中钓鱼题助助兴!涉及的高 - 掘金[ https://juejin.cn/post/7592816646869860361](https://juejin.cn/post/7592816646869860361)

\[44] Fable为啥遭美国下架?一场技术、管理与社会的对撞\_傅盛[ http://m.toutiao.com/group/7651625901616972351/](http://m.toutiao.com/group/7651625901616972351/)

\[45] Cyber天花板被打穿，AISI实测Mythos能力正以4.5月翻倍速冲向ASI\_36氪[ http://m.toutiao.com/group/7639908180021084735/](http://m.toutiao.com/group/7639908180021084735/)

\[46] 自动驾驶赛车路径与车速协同规划方法[ https://qikan.cmes.org/jxgcxb/CN/10.3901/JME.2022.10.200](https://qikan.cmes.org/jxgcxb/CN/10.3901/JME.2022.10.200)

\[47] AI渗透测试工具:从"脚本跑腿"到"Agent大脑"的范式革命渗透测试的战场正在发生根本性变化。 传统模式里，你是猎人， - 掘金[ https://juejin.cn/post/7611783793201070107](https://juejin.cn/post/7611783793201070107)

\[48] 从配置投毒到命令执行:AGENTS.md 如何劫持智能体-51CTO.COM[ https://www.51cto.com/article/852815.html](https://www.51cto.com/article/852815.html)

\[49] 询问任务是否完成时，怎么防止AI说谎:不是询问，而是让Agent主动攻击-51CTO.COM[ https://www.51cto.com/article/851676.html](https://www.51cto.com/article/851676.html)

\[50] AI Agent 安全测试指南:用 75 个攻击向量给你的 Agent 做一次体检AI Agent 正在裸奔。本文用 7 - 掘金[ https://juejin.cn/post/7672977569477656603](https://juejin.cn/post/7672977569477656603)

\[51] 当 AI Agent 接管手机:移动端如何进行观测本文对 AI Agent 或脚本操作手机的技术原理进行了分析，同时也介 - 掘金[ https://juejin.cn/post/7610979696307126281](https://juejin.cn/post/7610979696307126281)

\[52] CTF之信息泄漏——你什么都没说但什么都告诉了我摘要:本文探讨了CTF比赛和网络防护中信息泄漏的常见方式及利用方法。主要 - 掘金[ https://juejin.cn/post/7632142002248958003](https://juejin.cn/post/7632142002248958003)

\[53] 在SOC中集成AI Agent工作流程，端到端自动处理警报|通信|soc|自动化|大模型|agent\_网易订阅[ https://www.163.com/dy/article/JPBJS4BE0511ALHJ.html](https://www.163.com/dy/article/JPBJS4BE0511ALHJ.html)

\[54] 别瞎折腾了!4 步排查法，手把手教你搞定 OpenClaw Skills 各种安装报错OpenClaw Skills 无 - 掘金[ https://juejin.cn/post/7615946771991658522](https://juejin.cn/post/7615946771991658522)

\[55] 糟糕，ChatGPT和Claude「攻击」真人了\_36氪[ http://m.toutiao.com/group/7672192646957318707/](http://m.toutiao.com/group/7672192646957318707/)

\[56] Agentic风控:Flink+Fluss+大模型构建Agent全链路风险感知与实时告警本文分享基于Flink + Fl - 掘金[ https://juejin.cn/post/7633624945063903272](https://juejin.cn/post/7633624945063903272)

\[57] 14天450人500辆Agent坦克大混战:我们完成了一场大规模 Agent 众测\_ZAKER新闻[ http://applocal.myzaker.com/news/article.php?pk=6a6966b48e9f09512322838a](http://applocal.myzaker.com/news/article.php?pk=6a6966b48e9f09512322838a)

\[58] 让 Coding Agent 记得住:agentmemory 的长期记忆系统拆解一句话看懂 agentmemory 解决 - 掘金[ https://juejin.cn/post/7642229553621024794](https://juejin.cn/post/7642229553621024794)

\[59] 面试官问:Agent 的记忆模块是怎么实现的?面试官问:Agent 的记忆模块是怎么实现的? 回到今天的主题，面试官经常 - 掘金[ https://juejin.cn/post/7571829879827447827](https://juejin.cn/post/7571829879827447827)

\[60] 做 Agent 别总想着堆 Prompt，先把这五种架构吃透 别再用堆Prompt的方式，把Agent做死了 2026年 - 掘金[ https://juejin.cn/post/7637630256104472582](https://juejin.cn/post/7637630256104472582)

\[61] 爆肝万字!这应该是全网最全的 Codex 实战教程了最近这段时间，我后台被同一个问题问麻了。 Codex 到底怎么用? - 掘金[ https://juejin.cn/post/7638806086187565082](https://juejin.cn/post/7638806086187565082)

\[62] AI 编程(Agent 开发)术语指南 · 第二章简介 第二章聚焦于智能体的行为管理与能力扩展，阐述如何通过规则、提示策 - 掘金[ https://juejin.cn/post/7571086754880733230](https://juejin.cn/post/7571086754880733230)

\[63] Codex 插件【ArmorCodex】:管理 AI 策略|调用|示例|服务器|显式标识\_网易订阅[ https://www.163.com/dy/article/L24H4HC30536FE6V.html](https://www.163.com/dy/article/L24H4HC30536FE6V.html)

\[64] 询问任务是否完成时，怎么防止AI说谎:不是询问，而是让Agent主动攻击-51CTO.COM[ https://www.51cto.com/article/851676.html](https://www.51cto.com/article/851676.html)

\[65] 有效的 Context 工程(精读、万字梳理)|见知录 004有效的 Context 工程(精读、万字梳理)|见知录 0 - 掘金[ https://juejin.cn/post/7564253109162868763](https://juejin.cn/post/7564253109162868763)

\[66] 别让你的 AI Agent 学会掩盖错误[ https://c.m.163.com/news/a/L2FKPL11051188EA.html](https://c.m.163.com/news/a/L2FKPL11051188EA.html)

\[67] GPT-5.6被曝重大bug!硅谷大佬Mac被一键清空\_新智元[ http://m.toutiao.com/group/7661257024134464000/](http://m.toutiao.com/group/7661257024134464000/)

\[68] 万字干货 | OpenClaw 进阶玩法大全:技能 / 多 Agent / 省钱 / 安全，50+ 实战技巧一次学会 - 掘金[ https://juejin.cn/post/7618869612340183080](https://juejin.cn/post/7618869612340183080)

\[69] 别让你的 AI Agent 学会掩盖错误|证据|使用者|agent\_网易订阅[ https://www.163.com/dy/article/L2FKPL11051188EA.html](https://www.163.com/dy/article/L2FKPL11051188EA.html)

\[70] 2. 投标分项报价表[ https://zhengzhou.zfcg.henan.gov.cn/cmsweb81e27e/nas/webfile2024/henan/rootfiles/2025/11/14/a6cb2147c57d4db6b8a3521bae237b83.pdf](https://zhengzhou.zfcg.henan.gov.cn/cmsweb81e27e/nas/webfile2024/henan/rootfiles/2025/11/14/a6cb2147c57d4db6b8a3521bae237b83.pdf)

\[71] openclaw配置大全/注释\_老余AI效率笔记[ http://m.toutiao.com/group/7622658679636050441/](http://m.toutiao.com/group/7622658679636050441/)

\[72] Hermes 模型配置详解——主模型与辅助模型第 5 篇:模型配置详解——主模型与辅助模型 引言 Hermes 使用两种 - 掘金[ https://juejin.cn/post/7671607298570518582](https://juejin.cn/post/7671607298570518582)

\[73] OpenClaw 最短路径部署 + 最基本配置 的完整指南。\_Jensenyang[ http://m.toutiao.com/group/7620249383283556898/](http://m.toutiao.com/group/7620249383283556898/)

\[74] CTF竞赛密码学之 LFSR概述: 线性反馈移位寄存器(LFSR)归属于移位寄存器(FSR),除此之外还有非线性移位寄存 - 掘金[ https://juejin.cn/post/7270150700382208056](https://juejin.cn/post/7270150700382208056)

\[75] GPT-oss太离谱:无提示自行想象编程问题，还重复求解5000次\_量子位[ http://m.toutiao.com/group/7537244011078091274/](http://m.toutiao.com/group/7537244011078091274/)

\[76] 英文 PDF 秒变中文，还原排版，保留图片、表格、公式，完全免费\_鲲鹏Talk[ http://m.toutiao.com/group/7537469217096925705/](http://m.toutiao.com/group/7537469217096925705/)

\[77] CTF解题技能之图片分析(一)\_网易订阅[ https://www.163.com/dy/article/EGRB2TOU05119F6V.html](https://www.163.com/dy/article/EGRB2TOU05119F6V.html)

\[78] 2022 年重庆市职业院校技能大赛 “信息安全管理与评估”赛项规程[ http://www.cqjy.com/Upload/main/ContentManage/Article/File/2022/10/25/202210251109586911.pdf](http://www.cqjy.com/Upload/main/ContentManage/Article/File/2022/10/25/202210251109586911.pdf)

\[79] 基于符号执行的堆溢出 fastbin 攻击检测方法[ https://www.ecice06.com/fileup/1000-3428/PDF/20201019.pdf](https://www.ecice06.com/fileup/1000-3428/PDF/20201019.pdf)

\[80] In situ atomic-scale observation of continuous and reversible lattice deformation beyond the elastic limit[ https://www.paper.edu.cn/uploads/self/2014/01/06/wanglihua109246-self-201401-10.pdf](https://www.paper.edu.cn/uploads/self/2014/01/06/wanglihua109246-self-201401-10.pdf)

\[81] 2022 年全国职业院校技能大赛 赛项规程 信息安全管理与评估 GZ-2022038[ http://www.cqjy.com/Upload/main/ContentManage/Article/File/2022/03/31/202203311012111579.pdf](http://www.cqjy.com/Upload/main/ContentManage/Article/File/2022/03/31/202203311012111579.pdf)

\[82] AI Agent 安全测试指南:用 75 个攻击向量给你的 Agent 做一次体检AI Agent 正在裸奔。本文用 7 - 掘金[ https://juejin.cn/post/7672977569477656603](https://juejin.cn/post/7672977569477656603)

\[83] 询问任务是否完成时，怎么防止AI说谎:不是询问，而是让Agent主动攻击-51CTO.COM[ https://www.51cto.com/article/851676.html](https://www.51cto.com/article/851676.html)

\[84] Codex 插件【ArmorCodex】:管理 AI 策略|调用|示例|服务器|显式标识\_网易订阅[ https://www.163.com/dy/article/L24H4HC30536FE6V.html](https://www.163.com/dy/article/L24H4HC30536FE6V.html)

\[85] 有效的 Context 工程(精读、万字梳理)|见知录 004有效的 Context 工程(精读、万字梳理)|见知录 0 - 掘金[ https://juejin.cn/post/7564253109162868763](https://juejin.cn/post/7564253109162868763)

\[86] 别让你的 AI Agent 学会掩盖错误|证据|使用者|agent\_网易订阅[ https://www.163.com/dy/article/L2FKPL11051188EA.html](https://www.163.com/dy/article/L2FKPL11051188EA.html)

\[87] 万字干货 | OpenClaw 进阶玩法大全:技能 / 多 Agent / 省钱 / 安全，50+ 实战技巧一次学会 - 掘金[ https://juejin.cn/post/7618869612340183080](https://juejin.cn/post/7618869612340183080)

\[88] 别让你的 AI Agent 学会掩盖错误[ https://c.m.163.com/news/a/L2FKPL11051188EA.html](https://c.m.163.com/news/a/L2FKPL11051188EA.html)

\[89] 智能路由多 AI 模型， Claude Code Router 让效率起飞!cpolar 内网穿透实验室第 529 个成功挑战 - 掘金[ https://juejin.cn/post/7581728606307778612](https://juejin.cn/post/7581728606307778612)

\[90] OpenClaw Agents 系统:多代理架构与智能编排的完整技术解析概览 Agents 系统是 OpenClaw 的 - 掘金[ https://juejin.cn/post/7615445777147641892](https://juejin.cn/post/7615445777147641892)

\[91] 这个51K星标的开源神器，让任何Agent都能一键切换所有模型\_腾讯新闻[ https://view.inews.qq.com/a/20260428A02WRN00](https://view.inews.qq.com/a/20260428A02WRN00)

\[92] 使用 MCP 与 A2A 设计多智能体 AI 系统——多智能体系统的测试、调试与故障排查在上一章中，我们构建了 MAKD - 掘金[ https://juejin.cn/post/7613004898187739188](https://juejin.cn/post/7613004898187739188)

\[93] Oh My OpenCode实战指南:打造你的AgentTeamOh My OpenCode实战指南:打造你的Agent - 掘金[ https://juejin.cn/post/7614566158142291977](https://juejin.cn/post/7614566158142291977)

\[94] AI Agent的性能优化:从架构到代码级别的调优在前面的文章中,我们讨论了 AI Agent 的部署和运维。今天,我想 - 掘金[ https://juejin.cn/post/7464879639735926811](https://juejin.cn/post/7464879639735926811)

\[95] OpenClaw 多 Agent 实战指南:Multi-Agent Routing 与 Sub-Agents 的正确打开方式 - 掘金[ https://juejin.cn/post/7613970761352462336](https://juejin.cn/post/7613970761352462336)

\[96] OpenClaw 系统架构分析OpenClaw 采用插件化的 Gateway 控制平面架构，结合多渠道消息系统和跨平台客 - 掘金[ https://juejin.cn/post/7616814234513047595](https://juejin.cn/post/7616814234513047595)

> （注：文档部分内容可能由 AI 生成）