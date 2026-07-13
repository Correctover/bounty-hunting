# LiteLLM漏洞#8 — 提交包（READY TO SUBMIT）

## 提交方式
**GitHub Security Advisory (Private)**
链接：https://github.com/BerriAI/litellm/security/advisories/new

需要先登录GitHub（Correctover账号），如果2FA设备不在身边，用恢复码。

---

## 视频证据（已上传）
https://asciinema.org/a/VdCnjCTKCgYoxYTt

---

## 表单填写内容

### Ecosystem
pip

### Package name
litellm

### Affected versions
<= 1.92.0

### Patched versions
（留空）

### Severity
High (8.2)

### CVSS vector string
CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N

### Summary
MCP OpenAPI Tool Generator - SSRF via Unvalidated base_url in Tool Execution

### Description

#### Summary
The MCP OpenAPI-to-tool generator in LiteLLM validates the spec URL for SSRF when loading the OpenAPI specification, but does NOT validate the base_url extracted from the spec when executing generated tool functions. This allows an attacker to craft a malicious OpenAPI spec that redirects tool execution requests to internal services (cloud metadata, internal APIs, etc.).

#### Affected Component
- File: litellm/proxy/_experimental/mcp_server/openapi_to_mcp_generator.py
- Function: create_tool_function() inner tool_function()
- Lines: 369 (url = base_url + path), 416 (client.get), 418 (client.post)
- Contrast: async_safe_get at line 106 HAS SSRF protection, but tool execution does NOT

#### Vulnerability Details
1. load_openapi_spec_async() loads spec from URL - uses async_safe_get with SSRF protection
2. get_base_url() extracts servers[0].url from the spec - NO validation
3. create_tool_function() hardcodes base_url into the tool closure
4. When the tool is called, client.get/post(url) sends requests to the unvalidated base_url - NO SSRF protection

#### Proof of Concept (Verified)
Terminal recording: https://asciinema.org/a/VdCnjCTKCgYoxYTt

Steps in the recording:
1. Start mock HTTP server on 127.0.0.1:9999 simulating AWS metadata (169.254.169.254)
2. Call create_tool_function(base_url="http://127.0.0.1:9999")
3. Execute the returned tool_function()
4. HTTP request goes directly to mock server - SSRF CONFIRMED
5. Mock server returns fake IAM credentials: AccessKeyId=ASIA_FAKE_12345
6. user-agent header confirms: litellm/1.92.0

#### Impact
- Cloud environments: Attacker can access cloud instance metadata (AWS 169.254.169.254, GCP metadata server, Azure IMDS) to steal IAM credentials
- Internal network: Attacker can scan and interact with internal services
- Data exfiltration: Responses from internal services are returned directly to the MCP client

Attack scenario: Admin configures MCPServer pointing to attacker.com/spec.json. The spec contains servers URL pointing to http://169.254.169.254. Any user who calls generated MCP tools triggers requests to the metadata service. IAM credentials returned to attacker.

#### Suggested Fix
Apply the same SSRF validation used in load_openapi_spec_async (via async_safe_get / url_utils.validate_url) to the tool execution path.

#### Environment
- LiteLLM version: 1.92.0
- Python: 3.11
- OS: Linux

---

### CVE
（留空，让GitHub分配）

---

### Reporter
Guigui Wang (GitHub: Correctover)
