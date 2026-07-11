# Round 8: MLOps 框架安全扫描

## 扫描目标
- MLflow (2565 py files)
- BentoML (429 py files)  
- Ray (4657 py files)
- ZenML (快速评估)
- Prefect (快速评估)
- Gradio (快速评估)
- Google ADK (深度复查)

## 发现

### BentoML Runner RCE (不提交 - SECURITY.md 排除)
- **文件**: src/bentoml/_internal/server/runner_app.py:301
- **代码**: `params = pickle.loads(r_)` where `r_ = await request.body()`
- **触发**: HTTP header "args-number" != 1
- **PoC**: uid=0(root) confirmed
- **状态**: ❌ BentoML SECURITY.md 明确排除 runner service pickle 漏洞
- **Advisory**: advisories/bentoml-rce-advisory.md

### MLflow exec() (暂不提交 - 攻击面受限)
- **文件**: mlflow/genai/scorers/scorer_utils.py:179
- **代码**: `exec(func_def, import_namespace, local_namespace)`
- **保护**: `is_databricks_uri(get_tracking_uri())` 检查
- **UI端点**: handlers.py:6663 `_invoke_scorer_handler` 无auth但exec被databricks check阻断
- **注册端点**: handlers.py:5452 显式阻止 call_source
- **Pickle**: MLFLOW_ALLOW_PICKLE_DESERIALIZATION env var 防护
- **路径遍历**: validate_path_is_safe() 全面防护
- **SSRF**: gateway_proxy_handler 正则锁死路径

### Ray (未发现可直接利用的漏洞)
- eval() in variant_generator.py:461 → 设计特性
- pickle in serve/serialization.py → 内部序列化
- pickle in replica.py → proxy-to-replica 内部通信
- Dashboard: 无auth但功能限于集群管理

### Google ADK 修复状态
- v0.py:117 pickle.loads 仍然存在（旧数据库兼容）
- v1.py: 已移除 pickle，改用 JSON
- LATEST_SCHEMA_VERSION = "1" (新数据库用 v1)
- Migration 工具: `adk migrate session` 命令
- 结论: 已修复，旧用户在过渡期

### MLflow pickle 反序列化
- sklearn 加载: MLFLOW_ALLOW_PICKLE_DESERIALIZATION env var (默认 False)
- 需要显式设置环境变量才能触发
- 不算默认配置下的漏洞

### Gradio 快速评估
- 使用 safehttpx 防 SSRF
- 使用 is_in_or_equal 防路径遍历
- 未发现 pickle/exec 危险模式

### ZenML / Prefect
- 均无明确 bug bounty 计划
- 跳过

## 结论
Python AI/MLOps 框架的安全防护水平普遍较高：
- Haystack: allowlist + denylist + 参数验证 三重防护
- Pydantic-AI: 0 CRITICAL
- LangChain: 转向 ast.literal_eval
- MLflow: 多层防护 (env var + is_databricks_uri + validate_path)
- Gradio: safehttpx + is_in_or_equal
- BentoML: 唯一有明确 RCE 但被 SECURITY.md 排除

**最有价值的发现是 Google ADK 的"防护不一致性"模式**：
migration 修了但 production 没同步，这种因开发流程缺陷导致的静默失败，
是 CCS 方法论最擅长捕获的攻击面。

## 下一步
1. 等待 MSRC Case 126539 (AutoGen) 回复
2. 等待 Google VRP (ADK) 回复
3. 将 10 个 CLEAN 目标整理为 CCS 安全基准数据库
4. 起草防护不一致性方法论文章
5. 7/28 MCP 新规后扫描首批实现端
