#!/usr/bin/env bash
# Let the scanning tools target SPECIFIC private networks (your lab, a customer's internal range) without opening all of private space.
#
#   bash deploy/scripts/allow-private-targets.sh 192.168.20.0/24            # allow exactly this network (replaces the list)
#   bash deploy/scripts/allow-private-targets.sh 192.168.20.0/24 10.50.0.0/16
#   bash deploy/scripts/allow-private-targets.sh --show                      # what is allowed now
#   bash deploy/scripts/allow-private-targets.sh --clear                     # back to "no private targets"
#   options: --prod  use the production compose file   --dry-run  check only, change nothing   --no-restart  write .env, restart yourself
#
# Why not just MCP_ALLOW_PRIVATE_TARGETS=true? That opens ALL private space, including the platform's own Docker network
# (Postgres, Redis, MinIO, the Metasploit RPC), to anything that can start a scan or an AI tool call. Loopback, link-local and the
# cloud-metadata address stay blocked no matter what you list. This is only the network-level gate: which targets a PROJECT may
# scan is still controlled by that project's authorized scope.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
MODE=set; PROD=false; DRY=false; RESTART=true; NETS=()
for a in "$@"; do
  case "$a" in
    --show) MODE=show ;; --clear) MODE=clear ;; --prod) PROD=true ;; --dry-run) DRY=true ;; --no-restart) RESTART=false ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    -*) echo "Unknown option: $a"; exit 2 ;;
    *) NETS+=("$a") ;;
  esac
done
ENV_FILE="${SOCIS_ENV_FILE:-deploy/docker/.env}"
CF=docker-compose.dev.yml; [[ "$PROD" == true ]] && CF=docker-compose.prod.yml
COMPOSE="docker compose -f deploy/docker/$CF"
current() { grep -E '^MCP_ALLOWED_PRIVATE_NETS=' "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- || true; }

if [[ "$MODE" == show ]]; then _c=$(current); echo "Allowed private networks: ${_c:-<none>}"; exit 0; fi
if [[ "$MODE" == set && ${#NETS[@]} -eq 0 ]]; then echo "Give at least one network, for example 192.168.20.0/24 (or --show / --clear)."; exit 2; fi

# Docker's own networks on this host: refuse to open any range that overlaps them
DOCKER_NETS=""
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  DOCKER_NETS=$(docker network inspect $(docker network ls -q) -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null | tr '\n' ' ' || true)
elif [[ "$DRY" != true && "$RESTART" == true ]]; then
  echo "Docker is not available here, so the Docker-network overlap check and the restart cannot run. Use --dry-run or --no-restart."; exit 1
fi

VALUE=""
if [[ "$MODE" == set ]]; then
  VALUE=$(DOCKER_NETS="$DOCKER_NETS" python3 - "${NETS[@]}" << 'PYEOF'
import ipaddress, os, sys
PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]
NEVER = [ipaddress.ip_network(n) for n in ("127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8", "224.0.0.0/4", "100.64.0.0/10", "::1/128", "fe80::/10", "ff00::/8")]
docker = []
for tok in os.environ.get("DOCKER_NETS", "").split():
    try: docker.append(ipaddress.ip_network(tok, strict=False))
    except ValueError: pass
out, bad = [], []
for raw in sys.argv[1:]:
    for tok in raw.replace(",", " ").split():
        try: net = ipaddress.ip_network(tok, strict=False)
        except ValueError: bad.append(f"'{tok}' is not a network (write it like 192.168.20.0/24)"); continue
        if any(net.version == n.version and net.overlaps(n) for n in NEVER):
            bad.append(f"{net} overlaps a range that can never be allowed (loopback, link-local, cloud metadata)"); continue
        if not any(net.version == p.version and net.subnet_of(p) for p in PRIVATE):
            bad.append(f"{net} is not private space: tools can already reach public addresses, so there is nothing to allow"); continue
        if net.version == 4 and net.prefixlen < 16:
            bad.append(f"{net} is too broad (shortest allowed: /16). List the specific subnets you are authorized to test"); continue
        if net.version == 6 and net.prefixlen < 48:
            bad.append(f"{net} is too broad (shortest allowed: /48)"); continue
        hit = [str(d) for d in docker if net.version == d.version and net.overlaps(d)]
        if hit:
            bad.append(f"{net} overlaps a Docker network on this host ({', '.join(hit)}): that would expose the platform's own containers"); continue
        if str(net) not in out: out.append(str(net))
if bad:
    print("\n".join("  refused: " + b for b in bad), file=sys.stderr); sys.exit(3)
print(",".join(out))
PYEOF
  ) || { echo "Nothing was changed."; exit 3; }
fi

_c=$(current); echo "Current : ${_c:-<none>}"; echo "New     : ${VALUE:-<none>}"
if [[ "$DRY" == true ]]; then echo "(dry run: nothing written)"; exit 0; fi
[[ -f "$ENV_FILE" ]] || { echo "No $ENV_FILE yet: run the installer first."; exit 1; }
if grep -qE '^MCP_ALLOWED_PRIVATE_NETS=' "$ENV_FILE"; then sed -i "s|^MCP_ALLOWED_PRIVATE_NETS=.*|MCP_ALLOWED_PRIVATE_NETS=${VALUE}|" "$ENV_FILE"; else printf '\nMCP_ALLOWED_PRIVATE_NETS=%s\n' "$VALUE" >> "$ENV_FILE"; fi
echo "Saved to $ENV_FILE"
if [[ "$RESTART" == true ]]; then
  $COMPOSE up -d --force-recreate mcp_all
  echo "Tool servers restarted. Inside the container: MCP_ALLOWED_PRIVATE_NETS=$($COMPOSE exec -T mcp_all printenv MCP_ALLOWED_PRIVATE_NETS 2>/dev/null | tr -d '\r')"
else
  echo "Now run:  $COMPOSE up -d --force-recreate mcp_all"
fi
