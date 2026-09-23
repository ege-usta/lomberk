import urllib.request
import urllib.error
import json
import os
import sys

def create_branch(project_id: str, api_key: str, branch_name: str, parent_id: str = None) -> dict:
    url = f"https://console.neon.tech/api/v2/projects/{project_id}/branches"
    payload = {
        "branch": {
            "name": branch_name
        }
    }
    if parent_id:
        payload["branch"]["parent_id"] = parent_id
        
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json"
        },
        method="POST"
    )
    
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        print(f"Neon API Error: {e.read().decode()}", file=sys.stderr)
        raise
