import os
import requests
import json
import time

TOKEN = os.environ.get("GITHUB_TOKEN", "REPLACE_ME")
HEADERS = {
    "Authorization": f"token {TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

# Load baselines
with open("./recent_memory/project/monitor-baselines.json") as f:
    baselines = json.load(f)

issues_to_check = [
    ("crewAIInc/crewAI", 4877),
    ("crewAIInc/crewAI", 5802),
    ("crewAIInc/crewAI", 5888),
    ("crewAIInc/crewAI", 6025),
    ("microsoft/autogen", 7372),
    ("microsoft/autogen", 7405),
    ("microsoft/autogen", 7492),
    ("microsoft/autogen", 7353),
    ("microsoft/autogen", 7525),
    ("microsoft/autogen", 7770),
    ("langchain-ai/langgraph", 5672),
    ("langchain-ai/langgraph", 7303),
    ("microsoft/semantic-kernel", 13957),
    ("Tuttotorna/PHI-OMEGA-RUNTIME", 1),
    ("langchain-ai/langchain", 33787),
]

results = {}
changes = []

for repo, num in issues_to_check:
    key = f"{repo}#{num}"
    old_count = baselines["issues"].get(key, {}).get("count", 0)
    
    # Get issue info (comments count is in the issue object)
    url = f"https://api.github.com/repos/{repo}/issues/{num}"
    resp = requests.get(url, headers=HEADERS)
    
    if resp.status_code == 200:
        data = resp.json()
        current_count = data.get("comments", 0)
        status = data.get("state", "unknown")
        title = data.get("title", "")
        results[key] = {
            "old": old_count,
            "new": current_count,
            "status": status,
            "title": title,
            "diff": current_count - old_count
        }
        if current_count != old_count or status != baselines["issues"].get(key, {}).get("status", ""):
            changes.append({
                "repo": repo,
                "num": num,
                "key": key,
                "title": title,
                "old_count": old_count,
                "new_count": current_count,
                "status": status,
                "diff": current_count - old_count
            })
    else:
        results[key] = {"error": resp.status_code, "msg": resp.text[:200]}
    
    time.sleep(0.3)  # rate limit friendly

print("=== CHANGES ===")
if changes:
    for c in changes:
        print(f"{c['key']}: {c['old_count']} -> {c['new_count']} (diff: {c['diff']:+d}) status={c['status']} | {c['title'][:60]}")
else:
    print("NO CHANGES")

print("\n=== FULL STATUS ===")
for key, r in results.items():
    if "error" in r:
        print(f"{key}: ERROR {r['error']} - {r.get('msg','')}")
    else:
        marker = " *CHANGED*" if r['diff'] != 0 else ""
        print(f"{key}: {r['new']} comments (was {r['old']}) status={r['status']}{marker}")

# Output JSON for update
print("\n=== UPDATE_JSON ===")
update_data = {
    "last_updated": "2026-07-11T11:55:00+08:00",
    "issues": {}
}
for repo, num in issues_to_check:
    key = f"{repo}#{num}"
    r = results[key]
    if "error" not in r:
        update_data["issues"][key] = {
            "count": r["new"],
            "status": r["status"],
            "last_checked": "2026-07-11T11:55:00+08:00"
        }
    else:
        # Keep old data on error
        update_data["issues"][key] = baselines["issues"].get(key, {"count": 0, "status": "unknown", "last_checked": "2026-07-11T11:55:00+08:00"})

print(json.dumps(update_data, indent=2))

