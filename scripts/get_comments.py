import os
import requests
import json
import time

TOKEN = os.environ.get("GITHUB_TOKEN", "REPLACE_ME")
HEADERS = {
    "Authorization": f"token {TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

# Get latest 5 comments for the 2 changed issues
changed_issues = [
    ("crewAIInc/crewAI", 6025),
    ("langchain-ai/langchain", 33787),
]

for repo, num in changed_issues:
    print(f"\n{'='*80}")
    print(f"=== {repo}#{num} - Latest 5 comments ===")
    print(f"{'='*80}")
    
    url = f"https://api.github.com/repos/{repo}/issues/{num}/comments"
    params = {"per_page": 5, "page": 1}
    
    # Get total pages first
    resp = requests.get(url, headers=HEADERS, params={"per_page": 1})
    # Use Link header to find last page
    link_header = resp.headers.get("Link", "")
    
    # Actually, let's just get the last 5 by fetching page with offset
    # First get total count
    all_comments_url = f"https://api.github.com/repos/{repo}/issues/{num}/comments?per_page=100&page=1"
    
    # Simpler: get last page
    # For #6025 with 88 comments, page = ceil(88/100) = 1 (all on page 1)
    # For #33787 with 57 comments, page = 1
    
    resp = requests.get(url, headers=HEADERS, params={"per_page": 100, "page": 1})
    if resp.status_code == 200:
        comments = resp.json()
        # Get last 5
        last5 = comments[-5:]
        for c in last5:
            user = c.get("user", {}).get("login", "unknown")
            created = c.get("created_at", "")
            body = c.get("body", "")[:800]
            print(f"\n--- [{created}] @{user} ---")
            print(body)
    else:
        print(f"Error: {resp.status_code} - {resp.text[:200]}")
    
    time.sleep(0.5)

