@echo off
REM ==============================================
REM 免费 LLM Key 环境变量模板（薅羊毛清单）
REM 用法：注册领 key 后，把下面的 KEY 换成真实的，然后运行本脚本
REM 运行后需新开终端生效（setx 不刷新当前进程）
REM ==============================================

REM ── 白名单内（初赛合规，优先）──
setx ZHIPU_API_KEY "KEY"          REM 智谱 GLM-4.7-Flash（永久免费不限量？待验证）
setx QIANFAN_API_KEY "KEY"        REM 百度千帆 ERNIE-Speed/Lite（永久免费不限量？待验证）
setx HUNYUAN_API_KEY "KEY"        REM 腾讯混元-Lite（永久免费）
setx XFYUN_API_KEY "KEY"          REM 讯飞 Spark Lite（永久免费）
setx SILICONFLOW_API_KEY "KEY"    REM 硅基流动（2000-3000万token）
setx MOONSHOT_API_KEY "KEY"       REM 月之暗面 Kimi（500-1000万token）
setx ARK_API_KEY "KEY"            REM 字节豆包（200万token/天）

REM ── 已就绪 ──
REM MIMO_API_KEY 已有（小米 MiMo，已验证可用）

echo 完成！请新开终端后逐个验证：
echo   python -c "from llm.client import ai_chat; print(ai_chat([{'role':'user','content':'hi'}], provider='glm'))"
echo 换 provider 名：glm/baidu/tencent/xfyun/siliconflow/moonshot/ark/mimo
