#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Where does the time go? Measures the things that make the platform feel slow and says which one it is.
#
#   bash deploy/scripts/perf-check.sh [install-dir] [base-url]
#
# Reads only; changes nothing. Safe to run any time (it is most useful BEFORE and AFTER an update).
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
TARGET="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
BASE="${2:-http://localhost}"
DOCKER="${DOCKER_BIN:-docker}"
CF="${COMPOSE_FILE:-docker-compose.dev.yml}"
COMPOSE="$DOCKER compose -f $TARGET/deploy/docker/$CF"
ENVF="$TARGET/deploy/docker/.env"
if [[ -t 1 ]]; then B=$'\033[1m'; Y=$'\033[1;33m'; R=$'\033[0;31m'; G=$'\033[0;32m'; N=$'\033[0m'; else B=; Y=; R=; G=; N=; fi
H() { echo; echo "${B}── $* ──${N}"; }
FINDINGS=()
add() { FINDINGS+=("$1"); }

H "1. Host"
echo "cores: $(nproc 2>/dev/null || echo ?)   load (1/5/15 min): $(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo ?)"
read -r mem_total mem_avail swap_total swap_used < <(${PC_FREE:-free} -m 2>/dev/null | awk 'NR==2{t=$2;a=$7} NR==3{st=$2;su=$3} END{print t+0, a+0, st+0, su+0}')
echo "memory: ${mem_total:-?} MB total, ${mem_avail:-?} MB available   swap: ${swap_used:-0} MB used of ${swap_total:-0} MB"
# Swap that merely HOLDS old idle pages is harmless. What hurts is swapping RIGHT NOW (pages moving in/out) or no free memory.
swap_rate() {
  [[ -n "${PC_SWAP_RATE:-}" ]] && { echo "$PC_SWAP_RATE"; return; }
  local a b; a=$(awk '/^pswpin|^pswpout/{s+=$2} END{print s+0}' /proc/vmstat 2>/dev/null); sleep 2; b=$(awk '/^pswpin|^pswpout/{s+=$2} END{print s+0}' /proc/vmstat 2>/dev/null)
  echo $(( (b - a) / 2 ))
}
rate=$(swap_rate)
if (( ${rate:-0} > 100 )); then echo "swapping NOW: ${rate} pages/s"; add "The host is actively swapping (${rate} pages/s): memory is short right now, which slows everything. Free memory or lower container limits."
elif (( ${mem_total:-0} > 0 && ${mem_avail:-0} * 10 < ${mem_total:-0} )); then add "Only ${mem_avail} MB of ${mem_total} MB is free on the host: it is close to swapping. Free memory or lower container limits."
elif (( ${swap_used:-0} > 200 )); then echo "(swap holds ${swap_used} MB of old, idle pages and nothing is swapping now: harmless)"; fi
others=$($DOCKER ps --format '{{.Names}}' 2>/dev/null | grep -v '^socis_' | tr '\n' ' ')
[[ -n "$others" ]] && echo "other containers sharing this VM: $others"

H "2. Containers: restarts and out-of-memory kills"
printf '%-22s %-9s %-9s %-6s %s\n' name state restarts OOM "memory limit"
for svc in frontend backend postgres redis nginx; do
  id=$($COMPOSE ps -q "$svc" 2>/dev/null | head -1)
  [[ -z "$id" ]] && { printf '%-22s %s\n' "$svc" "(not running)"; continue; }
  line=$($DOCKER inspect -f '{{.State.Status}}|{{.RestartCount}}|{{.State.OOMKilled}}|{{.HostConfig.Memory}}' "$id" 2>/dev/null)
  IFS='|' read -r st rc oom mem <<< "$line"
  memh="unlimited"; [[ "${mem:-0}" -gt 0 ]] 2>/dev/null && memh="$((mem / 1024 / 1024)) MB"
  printf '%-22s %-9s %-9s %-6s %s\n' "$svc" "$st" "$rc" "$oom" "$memh"
  [[ "$oom" == true ]] && add "$svc was killed for running out of memory ($memh limit). Raise ${svc^^}_MEM in deploy/docker/.env (FRONTEND_HEAP_MB for the frontend), then recreate it."
  [[ "${rc:-0}" -gt 2 ]] 2>/dev/null && add "$svc has restarted $rc times. After every restart the frontend recompiles pages from scratch. Check: $COMPOSE logs --tail=40 $svc"
done
echo; $DOCKER stats --no-stream --format '{{.Name}}: cpu {{.CPUPerc}}   mem {{.MemUsage}}' 2>/dev/null | grep -E '^socis_' || echo "(docker stats unavailable)"
fe_id=$($COMPOSE ps -q frontend 2>/dev/null | head -1)
if [[ -n "$fe_id" ]]; then
  fe_limit=$($DOCKER inspect -f '{{.HostConfig.Memory}}' "$fe_id" 2>/dev/null); fe_limit_mb=$(( ${fe_limit:-0} / 1048576 ))
  fe_used=$($DOCKER stats --no-stream --format '{{.MemUsage}}' "$fe_id" 2>/dev/null | awk '{u=$1; if(u ~ /GiB/){sub(/GiB/,"",u); printf "%d", u*1024} else {sub(/MiB/,"",u); printf "%d", u}}')
  heap=$($COMPOSE exec -T frontend printenv NODE_OPTIONS 2>/dev/null | tr -d '\r' | sed -nE 's/.*--max-old-space-size=([0-9]+).*/\1/p')
  if (( fe_limit_mb > 0 && ${fe_used:-0} * 100 / fe_limit_mb > 60 )); then add "The frontend already uses ${fe_used} of its ${fe_limit_mb} MB limit while idle. Compiling a large page needs more, so it can stall or be killed. Set FRONTEND_MEM=2g in deploy/docker/.env and recreate it."; fi
  if [[ -n "$heap" ]] && (( fe_limit_mb > 0 && heap * 100 >= fe_limit_mb * 85 )); then add "Node's heap cap (${heap} MB) is not safely below the frontend's memory limit (${fe_limit_mb} MB): under load it outgrows the container and stalls or is killed. Raise FRONTEND_MEM or lower FRONTEND_HEAP_MB in deploy/docker/.env."; fi
  [[ -z "$heap" ]] && echo "(frontend has no Node heap cap: older compose file)"
fi

H "3. Frontend mode"
fe_env=$($COMPOSE exec -T frontend printenv NODE_ENV 2>/dev/null | tr -d '\r')
cfg=$(grep -E '^FRONTEND_TARGET=' "$ENVF" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '"'"'"'[:space:]')
echo "container NODE_ENV: ${fe_env:-unknown}    FRONTEND_TARGET in .env: ${cfg:-dev (default)}"

H "4. Database size and indexes"
dbq() { $COMPOSE exec -T postgres sh -c "psql -U \"\$POSTGRES_USER\" -d \"\$POSTGRES_DB\" -At -F' | ' -c \"$1\"" 2>/dev/null | tr -d '\r'; }
echo "largest tables:"; dbq "SELECT relname, n_live_tup||' rows', pg_size_pretty(pg_total_relation_size(relid)) FROM pg_stat_user_tables ORDER BY pg_total_relation_size(relid) DESC LIMIT 6" | sed 's/^/   /'
tr_size=$(dbq "SELECT coalesce(sum(length(raw_output)),0)/1048576 FROM scan_tool_results")
echo "raw tool output stored: ${tr_size:-?} MB"
[[ "${tr_size%%.*}" =~ ^[0-9]+$ && "${tr_size%%.*}" -gt 200 ]] && add "Stored raw tool output is ${tr_size%%.*} MB. Any query that loads it per scan is slow (the update makes list pages skip it)."
nix=$(dbq "SELECT count(*) FROM pg_indexes WHERE indexname LIKE 'ix_perf_%'")
echo "performance indexes present: ${nix:-?}"
[[ "${nix:-0}" == 0 ]] && add "The performance indexes are not created yet. The updated backend creates them in the background at startup (restart it once: $COMPOSE restart backend)."

H "5. API timing and payload size (what every page calls)"
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_admin.sh"
trap verify_admin_cleanup EXIT
verify_admin_create || true   # temporary admin so the probe works when the real admin has two-factor on
probe=$(bexec sh -c 'cd /app && python tests/perf_probe.py 2>&1' 2>/dev/null | tr -d '\r')
if [[ -z "$probe" || "$probe" == *"No such file"* ]]; then echo "(the probe ships with the update: it runs once you have synced and rebuilt)"; else echo "$probe"
  echo "$probe" | grep -q "^FAIL.*embeds heavy" && add "The scan list still returns raw tool output and analyses for every scan, and the dashboard, scans page and notification bell all call it. Update to the latest package."
  echo "$probe" | grep -q "^WARN" && add "Some API calls are slow (see section 5). With the database large and indexes missing, list pages scan whole tables."
fi

H "6. Page load through nginx (first visit vs second visit)"
printf '%-22s %10s %10s\n' route "1st (s)" "2nd (s)"
worst1=0; worst2=0; HUNG=(); PAGE_MAX="${PAGE_MAX:-150}"
for route in /login /dashboard /scans /projects /vulnerabilities /findings /reports /workflows /ai-chat /settings; do
  t1=$(curl -s -o /dev/null -w '%{time_total}' --max-time "$PAGE_MAX" "$BASE$route" 2>/dev/null || echo 0)
  t2=$(curl -s -o /dev/null -w '%{time_total}' --max-time "$PAGE_MAX" "$BASE$route" 2>/dev/null || echo 0)
  if awk -v a="$t1" -v b="$t2" -v m="$PAGE_MAX" 'BEGIN{exit !(a>=m-1 || b>=m-1)}'; then printf '%-22s %10s %10s\n' "$route" "TIMEOUT" "TIMEOUT"; HUNG+=("$route"); continue; fi
  printf '%-22s %10s %10s\n' "$route" "$t1" "$t2"
  worst1=$(awk -v a="$worst1" -v b="$t1" 'BEGIN{print (b>a)?b:a}'); worst2=$(awk -v a="$worst2" -v b="$t2" 'BEGIN{print (b>a)?b:a}')
done
if ((${#HUNG[@]} > 0)); then
  echo; echo "${R}No answer within ${PAGE_MAX} s: ${HUNG[*]}${N}"
  echo "recent frontend log lines that look relevant:"
  $COMPOSE logs --tail=300 frontend 2>/dev/null | grep -iE "out of memory|heap|FATAL|ENOMEM|killed|Error:|Compiling" | tail -6 | sed 's/^/   /'
  add "These pages never answered within ${PAGE_MAX} s (even on the second try): ${HUNG[*]}. The dev server is stalled or out of memory while compiling them (a page that imports other big pages is especially heavy). Check the log lines above, give the frontend more memory, or switch to the production build: bash deploy/scripts/frontend-mode.sh prod"
fi
slow_first=$(awk -v a="$worst1" -v b="$worst2" 'BEGIN{print (a>3 && a>3*b)?1:0}')
if [[ "$fe_env" == development && "$slow_first" == 1 ]]; then
  add "The frontend runs in DEVELOPMENT mode (slowest first visit ${worst1}s, repeat ${worst2}s): each page is compiled the first time you open it, and again after every restart. Fix: bash deploy/scripts/frontend-mode.sh prod"
fi

H "Diagnosis"
if ((${#FINDINGS[@]} == 0)); then echo "${G}Nothing obviously wrong found.${N} If it still feels slow, send me this whole output."
else n=1; for f in "${FINDINGS[@]}"; do echo "${Y}$n.${N} $f"; n=$((n+1)); done; fi
exit 0
