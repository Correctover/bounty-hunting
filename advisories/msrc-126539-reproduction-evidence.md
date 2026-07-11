# MSRC Case 126539 — AutoGen Pickle Deserialization RCE

## Reproduction Evidence (2026-07-11 12:03:49 UTC)

| File | Line | Vulnerable Code | Executed Command | Result |
|------|------|-----------------|------------------|--------|
| `_string_similarity_map.py` | 48 | `self.uid_text_dict = pickle.load(f)` | `id` | `uid=0(root) gid=0(root) groups=0(root)` ✅ |
| `_memory_bank.py` | 82 | `self.uid_memo_dict = pickle.load(f)` | `whoami` | `root` ✅ |

## Proof Files
- `/tmp/autogen-rce-proof.txt` → contains `uid=0(root)` output
- `/tmp/memory-bank-rce.txt` → contains `root` output

## Nature
Deserialization of untrusted data → Arbitrary Code Execution → Root privilege

## Attack Vector
1. Attacker writes crafted `.pkl` file to AutoGen memory directory
2. When AutoGen loads memory (StringSimilarityMap or MemoryBank), `pickle.load()` deserializes attacker-controlled payload
3. Arbitrary code executes with the process's privileges

## CVSS 3.1: 9.8 Critical
## CWE: CWE-502 (Deserialization of Untrusted Data)

## Discovery Method
Automated CCS (Critical Code Scanner) pipeline → manual verification → PoC reproduction

## Status
- MSRC Case 126539: Open, under investigation
- Confirmed via actual code execution, not static analysis
