#!/usr/bin/env python3
"""Correctover MCS — Source Code Vulnerability Hunter (AST-based)"""
import ast, os, sys, json
from dataclasses import dataclass, asdict

@dataclass
class Finding:
    severity: str; rule: str; file: str; line: int; code: str; detail: str; function: str

SKIP_DIRS = {"test","tests","__pycache__","docs","examples","example","vendor",
             "node_modules",".git",".tox","migrations","fixtures","stubs",
             "typings",".mypy_cache","build","dist","egg-info","third_party",
             ".venv","venv","env","sandbox","benches","benchmarks","_examples"}

def should_skip(fp):
    parts = os.path.relpath(fp).split(os.sep)
    for p in parts:
        lo = p.lower()
        if lo in SKIP_DIRS or lo.startswith("test_") or lo.startswith("_test"):
            return True
    return False

def get_func(tree, lineno):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, 'end_lineno', node.lineno + 50)
            if node.lineno <= lineno <= end:
                return node.name
    return "<module>"

def scan_file(fpath, prefix):
    if should_skip(fpath): return []
    try:
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            src = f.read()
    except: return []
    if len(src) > 500000: return []
    try:
        tree = ast.parse(src, filename=fpath)
    except: return []
    lines = src.split('\n')
    rel = os.path.relpath(fpath, prefix)
    findings = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call): continue
        fn = node.func
        ln = node.lineno
        code = lines[ln-1].strip()[:120] if ln <= len(lines) else ""
        func = get_func(tree, ln)

        # eval/exec RCE
        if isinstance(fn, ast.Name) and fn.id in ('eval','exec'):
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                continue
            findings.append(Finding("CRITICAL","EVAL_RCE",rel,ln,code,
                f"{fn.id}() in {func}() with dynamic arg",func))

        # pickle/cloudpickle/dill RCE
        if isinstance(fn, ast.Attribute) and fn.attr in ('loads','load'):
            if isinstance(fn.value, ast.Name) and fn.value.id in ('pickle','cloudpickle','dill'):
                findings.append(Finding("CRITICAL","PICKLE_RCE",rel,ln,code,
                    f"{fn.value.id}.{fn.attr}() in {func}()",func))

        # subprocess shell=True
        if isinstance(fn, ast.Attribute) and fn.attr in ('run','call','Popen','check_output','check_call'):
            is_sub = (isinstance(fn.value, ast.Name) and fn.value.id == 'subprocess')
            if is_sub:
                for kw in node.keywords:
                    if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        findings.append(Finding("CRITICAL","SHELL_INJECT",rel,ln,code,
                            f"subprocess.{fn.attr}(shell=True) in {func}()",func))

        # os.system
        if isinstance(fn, ast.Attribute) and fn.attr == 'system':
            if isinstance(fn.value, ast.Name) and fn.value.id == 'os':
                findings.append(Finding("HIGH","OS_SYSTEM",rel,ln,code,
                    f"os.system() in {func}()",func))

        # yaml.load without SafeLoader
        if isinstance(fn, ast.Attribute) and fn.attr == 'load':
            if isinstance(fn.value, ast.Name) and fn.value.id == 'yaml':
                safe = False
                for kw in node.keywords:
                    if kw.arg == 'Loader':
                        if isinstance(kw.value, ast.Attribute) and 'Safe' in kw.value.attr:
                            safe = True
                        elif isinstance(kw.value, ast.Name) and 'Safe' in kw.value.id:
                            safe = True
                if not safe:
                    findings.append(Finding("HIGH","YAML_UNSAFE",rel,ln,code,
                        f"yaml.load() without SafeLoader in {func}()",func))

        # SSRF: HTTP call with dynamic URL (f-string or binop)
        if isinstance(fn, ast.Attribute) and fn.attr in ('get','post','put','delete','patch','request','open'):
            url_arg = node.args[0] if node.args else None
            if not url_arg:
                for kw in node.keywords:
                    if kw.arg == 'url': url_arg = kw.value; break
            if url_arg and isinstance(url_arg, (ast.JoinedStr, ast.BinOp)):
                lib = ""
                if isinstance(fn.value, ast.Name): lib = fn.value.id
                if lib in ('requests','httpx','aiohttp','urllib','client','session','http_client','self'):
                    findings.append(Finding("HIGH","SSRF_UNVALIDATED",rel,ln,code,
                        f"HTTP {fn.attr}() with dynamic URL in {func}()",func))

        # Path traversal: open() with dynamic path
        if isinstance(fn, ast.Name) and fn.id == 'open':
            path_arg = node.args[0] if node.args else None
            if path_arg and isinstance(path_arg, (ast.JoinedStr, ast.BinOp)):
                findings.append(Finding("HIGH","PATH_TRAVERSAL",rel,ln,code,
                    f"open() with dynamic path in {func}()",func))

        # Dynamic import
        if isinstance(fn, ast.Name) and fn.id == '__import__':
            if node.args and not isinstance(node.args[0], ast.Constant):
                findings.append(Finding("MEDIUM","DYNAMIC_IMPORT",rel,ln,code,
                    f"__import__() with dynamic arg in {func}()",func))

    return findings

def scan_repo(path):
    name = os.path.basename(path)
    all_f = []; scanned = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS and not d.startswith('.')]
        for f in files:
            if not f.endswith('.py'): continue
            fp = os.path.join(root, f)
            all_f.extend(scan_file(fp, path))
            scanned += 1
    sev = {}; rules = {}
    for f in all_f:
        sev[f.severity] = sev.get(f.severity, 0) + 1
        rules[f.rule] = rules.get(f.rule, 0) + 1
    return {"repo": name, "files": scanned, "total": len(all_f),
            "by_severity": sev, "by_rule": rules,
            "findings": [asdict(f) for f in all_f]}

# Main
targets = sys.argv[1:]
if not targets:
    print("Usage: source_hunter.py <repo1> [repo2 ...]")
    sys.exit(1)

os.makedirs("/tmp/hunt_reports", exist_ok=True)
print("="*60)
print("  Correctover MCS — Source Code Vulnerability Hunter")
print(f"  Targets: {len(targets)}")
print("="*60)

grand = []; tc = th = 0
for repo in targets:
    if not os.path.isdir(repo): continue
    r = scan_repo(repo)
    grand.append(r)
    c = r["by_severity"].get("CRITICAL",0); h = r["by_severity"].get("HIGH",0)
    tc += c; th += h
    icon = "🔴" if c > 0 else ("🟡" if h > 0 else "✅")
    print(f"\n{icon} {r['repo']:30s} | {r['files']:4d} files | C:{c} H:{h} M:{r['by_severity'].get('MEDIUM',0)}")
    if r["by_rule"]: print(f"   Rules: {dict(r['by_rule'])}")
    for f in r["findings"]:
        if f["severity"] in ("CRITICAL","HIGH"):
            print(f"   🔴[{f['severity']}] {f['rule']} | {f['file']}:{f['line']}")
            print(f"      {f['code'][:90]}")
    with open(f"/tmp/hunt_reports/{r['repo']}-report.json","w") as fh:
        json.dump(r, fh, indent=2)

print(f"\n{'='*60}")
print(f"  Total: {sum(r['total'] for r in grand)} findings ({tc} CRITICAL, {th} HIGH)")
print(f"  Reports: /tmp/hunt_reports/")
