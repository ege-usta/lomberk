"""Pretty-prints gateway JSON for the recorded demo. Usage: ... | python3 demo/fmt.py agent|human"""
import json
import sys

r = json.load(sys.stdin)
if sys.argv[1] == "agent":
    r = r["results"][0]
    print(f"  -> {r['status'].upper()}: {r['message']}")
    if r.get("checkpoint_id"):
        with open("/tmp/rowback-demo-cp", "w") as f:
            f.write(r["checkpoint_id"])
else:
    print(f"  -> {r['status'].upper()} ({r.get('rows_affected', 0)} rows)")
