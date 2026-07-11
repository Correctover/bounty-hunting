# 全量狩猎最终总结

## 扫描统计

| 目标 | 文件数 | 结果 |
|------|--------|------|
| autogen v0.14.0 | ~200 | ✅ captainagent exec() RCE MSRC 提交 |
| haystack 2.31.0 | ~300 | ✅ import_class_by_name RCE CVD 提交 + PoC 验证 |
| crewai 1.15.2 | ~150 | ✅ MSRC Case 126356 |
| tensorflow 2.18.0 | 1,835 | ❌ 全 FP |
| jax 0.10.2 | 617 | ❌ 全 FP |
| azure- / msal* | 402 | ❌ 全 FP |
| langchain_community | 1,204 | ❌ 全 FP |
| langgraph / chromadb / qdrant / weaviate / pinecone | ~500 | ❌ 全 FP |
| fastapi / flask / playwright / guidance / SK / others | ~500 | ❌ 全 FP |
| **总计** | **~5,600** | **4 真实漏洞** |

## 管道状态

- **4 个真实漏洞已在管道中**
- **潜在收入: $20K-$150K**
- TensorFlow 扫描验证了工具对大型项目（1,835文件）的稳定性

## 日期
2026-07-11
