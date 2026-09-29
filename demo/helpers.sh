# Short commands for the recorded demo (demo/demo.tape). Source it from the repo root: . demo/helpers.sh
GW=${GW:-http://localhost:8000}
DB=${DB:-undogate-db-1}

agent() {  # an AI agent sends SQL with the agent key
  curl -s -H "X-API-Key: demo-agent-key" -H 'Content-Type: application/json' \
    -X POST "$GW/v1/execute" -d "{\"sql\": \"$1\"}" | python3 demo/fmt.py agent
}
human() {  # approve | undo the last held request, with the admin key
  curl -s -H "X-API-Key: demo-admin-key" -X POST "$GW/v1/checkpoints/$(cat /tmp/undogate-demo-cp)/$1" | python3 demo/fmt.py human
}
rows() {
  docker exec "$DB" psql -U test -d pocketos -tAc \
    "select 'users: ' || (select count(*) from users) || '   payments: ' || (select count(*) from payments)"
}
