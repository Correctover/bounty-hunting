# Round 7: Bounty Hunting Campaign Summary
**Date:** 2026-07-11  
**Operator:** Correctover  
**Result:** 3 confirmed RCEs, 15 targets scanned, 10+ submissions filed

## Confirmed Vulnerabilities

### 1. Google ADK Pickle Deserialization RCE (CVSS 9.8)
- **File:** `sessions/schemas/v0.py:117` → `pickle.loads(value)` from database
- **Class:** `DynamicPickleType.process_result_value()`
- **Attack Vector:** DB write → pickle deserialization → RCE
- **Key Evidence:** Migration tool built `_RestrictedUnpickler` but production code missed the fix
- **Impact:** ADK 1.19.0-1.21.0 (MySQL/Spanner backend)
- **Submission:** Google VRP via secure@google.com
- **Expected Bounty:** $10K-$30K

### 2. Microsoft AutoGen Pickle RCE ×2 (CVSS 9.8)
- **File 1:** `_string_similarity_map.py:48` → `pickle.load(f)` from uid_text_dict.pkl
- **File 2:** `_memory_bank.py:82` → `pickle.load(f)` from uid_memo_dict.pkl
- **Proof:** uid=0(root) confirmed in sandbox
- **Submission:** MSRC Case 126539
- **Expected Bounty:** $5K-$10K

## Targets Scanned (Clean)
- Pydantic-AI: 0 CRITICAL
- LangChain: ast.literal_eval migration complete
- Haystack: Triple-layer serialization security (allowlist+denylist+param validation)
- AutoGPT: 1466 py files, 0 pickle.load
- LlamaIndex: 2 new pickle locations (low value - local file paths)
- GitHub MCP Server: Go code, manually reviewed
- Playwright MCP: TypeScript, hardened
- Azure DevOps MCP: No direct injection
- Claude Plugins: 117 CRITICAL all false positives
- MCP Fetch Server: SSRF theoretical but design-level
- MCP Git Server: All params have `-` prefix rejection

## Submissions Filed
- **MSRC Cases:** 126539 (AutoGen), 126356 (CrewAI), 126359 (Semantic Kernel)
- **Google VRP:** ADK Pickle RCE (email to secure@google.com)
- **GitHub Issues:** 9 issues across ag2, crewAI, llama_index, litellm, mcp-server-docker, fetch-mcp, desktop-commander, magic-mcp

## Methodology: Protection Inconsistency Detection
Key insight: Google ADK vulnerability was not "unsafe pickle usage" but "fixed in migration, missed in production". This pattern - where security fixes are applied in one code path but not another - is a systematic weakness that CCS methodology is uniquely positioned to detect.

## Next Targets
- MLOps frameworks: MLflow, BentoML, Ray
- Protection consistency scans on clean targets
- MCP spec compliance scanning (July 28 deadline)
