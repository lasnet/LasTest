#!/usr/bin/env bash
# End-to-end check for a prebuilt LasTest image. Creates only its own
# containers, network and volume, then removes them.
set -euo pipefail

if [[ -z "${LASTEST_IMAGE:-}" ]]; then
  echo "LASTEST_IMAGE must reference a published image by digest" >&2
  exit 2
fi
if [[ "$LASTEST_IMAGE" != *"@sha256:"* ]]; then
  echo "LASTEST_IMAGE must use an immutable @sha256 digest, not a tag" >&2
  exit 2
fi

API="laste2e-api-$$"
WORKER="laste2e-worker-$$"
VOLUME="laste2e-data-$$"
NETWORK="laste2e-net-$$"
PORT="${LASTEST_E2E_PORT:-$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)}"
PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
BASE="http://127.0.0.1:${PORT}"

cleanup() {
  docker rm -f "$API" "$WORKER" >/dev/null 2>&1 || true
  docker volume rm "$VOLUME" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

wait_ready() {
  for _ in $(seq 1 60); do
    if curl -fsS "${BASE}/api/health/ready" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "API did not become ready" >&2
  docker logs "$API" >&2 || true
  return 1
}

cli() {
  docker exec -i "$API" lastest --data-dir /data "$@"
}

echo "[1/9] isolated network and volume"
docker network create "$NETWORK" >/dev/null
docker volume create "$VOLUME" >/dev/null

echo "[2/9] start serve and worker as unprivileged processes"
docker run -d --name "$API" --network "$NETWORK" --network-alias api.lastest.test \
  -p "127.0.0.1:${PORT}:8080" \
  -v "${VOLUME}:/data" \
  -e LASTEST_DATA_DIR=/data -e LASTEST_BIND=0.0.0.0:8080 \
  -e LASTEST_INTERNAL_RANGES=172.16.0.0/12 -e LASTEST_LOG_LEVEL=warn \
  --read-only --tmpfs /tmp:size=64m,mode=1777 --cap-drop ALL \
  --security-opt no-new-privileges:true "$LASTEST_IMAGE" serve >/dev/null
docker run -d --name "$WORKER" --network "$NETWORK" \
  -v "${VOLUME}:/data" \
  -e LASTEST_DATA_DIR=/data -e LASTEST_INTERNAL_RANGES=172.16.0.0/12 \
  -e LASTEST_LOG_LEVEL=warn --read-only --tmpfs /tmp:size=64m,mode=1777 \
  --cap-drop ALL --security-opt no-new-privileges:true "$LASTEST_IMAGE" worker >/dev/null
wait_ready

echo "[3/9] create the first administrator through the setup API"
SETUP_CODE="$(cli admin setup-code | python3 -c 'import json,sys; print(json.load(sys.stdin)["code"])')"
printf '%s\n%s\n' "$SETUP_CODE" "$PASSWORD" \
  | python3 -c 'import json,sys; code,password=sys.stdin.read().splitlines(); print(json.dumps({"code":code,"username":"admin","password":password}))' \
  | curl -fsS -X POST "${BASE}/api/auth/setup" -H "Origin: $BASE" \
      -H 'Content-Type: application/json' --data @- >/dev/null
unset SETUP_CODE

echo "[4/9] CLI login and project creation"
cli auth login --username admin --password-stdin --api-url http://127.0.0.1:8080 <<<"$PASSWORD" >/dev/null
PROJECT_JSON="$(cli project create --name e2e-stand --client local --description "isolated e2e")"
PROJECT_ID="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["project"]["id"])' <<<"$PROJECT_JSON")"

echo "[5/9] approve scope for the API container host"
docker exec -i "$API" sh -c 'cat > /tmp/rules.json' <<'JSON'
[
  {"kind": "exact_domain", "value": "api.lastest.test"},
  {"kind": "cidr", "value": "172.16.0.0/12"}
]
JSON
cli scope update --project "$PROJECT_ID" --rules-file /tmp/rules.json \
  --expected-version 1 --approve >/dev/null

echo "[6/9] run a real HTTP probe against the isolated API"
JOB_JSON="$(cli job submit --project "$PROJECT_ID" --task-type http.probe \
  --params '{"targets":["http://api.lastest.test:8080/api/health/live"],"mode":"url"}' \
  --idempotency-key e2e-http-1)"
JOB_ID="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["job"]["id"])' <<<"$JOB_JSON")"
STATUS="queued"
for _ in $(seq 1 60); do
  STATUS_JSON="$(cli job status --id "$JOB_ID")"
  STATUS="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["job"]["status"])' <<<"$STATUS_JSON")"
  if [[ "$STATUS" =~ ^(succeeded|partial|failed|cancelled)$ ]]; then
    break
  fi
  sleep 1
done
if [[ "$STATUS" != "succeeded" ]]; then
  echo "job finished with $STATUS" >&2
  docker logs "$WORKER" >&2 || true
  exit 1
fi

echo "[7/9] dashboard and report use persisted observations"
cli report export --project "$PROJECT_ID" --format json --output /tmp/report.json
docker exec "$API" sh -eu -c 'grep -q "e2e-stand" /tmp/report.json && grep -q "\"http\"" /tmp/report.json'
LOGIN_JSON="$(python3 -c 'import json,sys; print(json.dumps({"username":"admin","password":sys.stdin.read().rstrip("\n"),"client":"cli"}))' <<<"$PASSWORD" \
  | curl -fsS -X POST "${BASE}/api/auth/login" \
      -H 'Content-Type: application/json' --data @-)"
TOKEN="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' <<<"$LOGIN_JSON")"
curl -fsS -H "Authorization: Bearer $TOKEN" \
  "${BASE}/api/projects/${PROJECT_ID}/dashboard" >/dev/null

echo "[8/9] restart both processes and verify history survives"
docker restart "$WORKER" >/dev/null
docker restart "$API" >/dev/null
wait_ready
PERSISTED="$(cli job status --id "$JOB_ID")"
python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["job"]["status"]=="succeeded"' <<<"$PERSISTED"

echo "[9/9] verify runtime excludes Go/Python/compilers and uses a non-root user"
docker run --rm --entrypoint /usr/local/bin/subfinder "$LASTEST_IMAGE" -version
cli task-types | python3 -c 'import json,sys; items=json.load(sys.stdin)["task_types"]; assert any(item["name"]=="subdomains.subfinder" and item["available"] for item in items)'
docker run --rm --entrypoint sh "$LASTEST_IMAGE" -eu -c \
  '! command -v go && ! command -v cargo && ! command -v python3 && ! command -v gcc'
IMAGE_USER="$(docker image inspect --format '{{.Config.User}}' "$LASTEST_IMAGE")"
if [[ "$IMAGE_USER" != "10001:10001" ]]; then
  echo "unexpected runtime user: $IMAGE_USER" >&2
  exit 1
fi

echo "LasTest e2e passed for $LASTEST_IMAGE"
