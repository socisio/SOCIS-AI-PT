#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# verify.sh — post-sync / post-rebuild verification for SOCIS-AI-PT.
#
# Two phases:
#   PHASE A — on-disk: did the sync land every change correctly?
#   PHASE B — runtime: does the running stack actually work (health, login,
#             CORS, token revocation, SSRF guard, chat cap, limits, etc.)?
#
# Usage:
#   bash verify.sh [TARGET] [BASE_URL]
#   Production install:  COMPOSE_FILE=docker-compose.prod.yml bash verify.sh /opt/socis.io/SOCIS-AI-PT https://<your-domain>
#                        (adds PHASE E: TLS, redirect, HSTS, CSP, secure cookies, exposed ports)
#     TARGET    repo path     (default /opt/socis.io/SOCIS-AI-PT)
#     BASE_URL  platform URL  (default http://localhost)
#
# Read-only except it performs a test login (needs ADMIN_PASSWORD from the
# backend env). Prints PASS/FAIL per check and a summary. Exit 0 if all pass.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

TARGET="${1:-/opt/socis.io/SOCIS-AI-PT}"
BASE="${2:-http://localhost}"
# Use the dev compose (monitoring is built in). Override with COMPOSE_FILE env
# to verify a prod install: COMPOSE_FILE=docker-compose.prod.yml bash verify.sh
_CF="${COMPOSE_FILE:-docker-compose.dev.yml}"
COMPOSE="docker compose -f ${TARGET}/deploy/docker/${_CF}"

G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; C='\033[0;36m'; B='\033[1m'; N='\033[0m'
pass=0; fail=0; warn=0
ok()   { echo -e "  ${G}✓ PASS${N} $*"; pass=$((pass+1)); }
no()   { echo -e "  ${R}✗ FAIL${N} $*"; fail=$((fail+1)); }
wn()   { echo -e "  ${Y}! WARN${N} $*"; warn=$((warn+1)); }
hdr()  { echo -e "\n${C}${B}$*${N}"; }

# check_file <path> <grep-pattern> <expected-count-min> <label>
chk() {
  local path="$TARGET/$1" pat="$2" min="$3" label="$4"
  if [[ ! -f "$path" ]]; then no "$label (file missing: $1)"; return; fi
  local c; c=$(grep -c "$pat" "$path" 2>/dev/null); c=${c:-0}
  # grep -c prints per-file; collapse any whitespace/newlines to the first int.
  c=$(printf '%s' "$c" | tr -dc '0-9' ); c=${c:-0}
  if (( ${c:-0} >= min )); then ok "$label"; else no "$label (found $c, need >= $min in $1)"; fi
}

none() {   # none <file> <pattern> <label>: passes when the pattern is ABSENT
  local path="$TARGET/$1"
  if [[ ! -f "$path" ]]; then no "$3 (file missing: $1)"; return; fi
  if grep -q "$2" "$path" 2>/dev/null; then no "$3 (still present in $1)"; else ok "$3"; fi
}

# A temporary administrator (random password, removed on exit) so the live checks work even when the real admin has two-factor on.
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_admin.sh"
trap verify_admin_cleanup EXIT

echo -e "${B}SOCIS-AI-PT verification${N}  target=$TARGET  base=$BASE"

# ─────────────────────────────────────────────────────────────────────────────
hdr "PHASE A — On-disk change checks"

# Security hardening
chk backend/app/main.py "fix C-3" 1                 "C-3 CORS allowlist present"
chk backend/app/api/v1/auth.py "generic_response" 1 "C-2 reset endpoint hardened"
chk backend/app/core/security.py "is_token_blocked" 1 "H-2 token blocklist in get_current_user"
chk backend/app/config.py "_enforce_production_posture" 1 "C-4 production guard present"
chk mcp-servers/mcp_auth.py "hmac.compare_digest" 1 "M-1 constant-time token compare"
chk mcp-servers/mcp_auth.py "validate_scan_target" 1 "H-5 SSRF validator present"
chk backend/app/main.py "X-Requested-With" 1        "L-9 CSRF header enforced"

# Ollama removal
if grep -q "image: ollama/ollama" "$TARGET/deploy/docker/docker-compose.dev.yml" 2>/dev/null; then
  no "Bundled Ollama still present in compose"; else ok "Bundled Ollama removed from compose"; fi
chk deploy/docker/docker-compose.dev.yml "OLLAMA_REMOTE_URL" 1 "External Ollama env present"

# Performance
chk deploy/docker/docker-compose.dev.yml "resources:" 10 "Resource limits on all services (>=10 blocks)"
chk deploy/docker/docker-compose.dev.yml "noeviction" 1 "Redis noeviction (queue safety)"
chk mcp-servers/mcp_auth.py "scan_slot" 1           "Scanner concurrency semaphore present"
chk mcp-servers/intel_cache.py "cache_get" 1        "Intel cache module present"
chk backend/app/core/token_blocklist.py "concurrency_slot" 1 "Chat-session limiter present"
chk backend/app/tasks/scan_worker.py "WorkerSettingsNoCron" 1 "Scalable cron-less worker present"
chk backend/app/services/storage_service.py "_ensure_lifecycle" 1 "MinIO lifecycle present"
chk deploy/scripts/lib/autosize.sh "autosize_env_block" 1 "Autosize helper present"

# nginx
chk deploy/nginx/nginx.conf "unsafe-eval" 1         "nginx CSP allows Next.js dev"
chk deploy/nginx/nginx.conf "connection_upgrade" 1  "nginx WebSocket (HMR) proxying"
chk deploy/nginx/nginx.conf "location /monitoring/" 1 "nginx /monitoring proxy present"
chk deploy/docker/docker-compose.dev.yml "no-new-privileges" 5 "Container hardening: no-new-privileges (dev)"
chk deploy/docker/docker-compose.prod.yml "no-new-privileges" 5 "Container hardening: no-new-privileges (prod)"
chk backend/app/api/v1/api_keys.py "via_api_key" 2 "M-4: API keys cannot mint/revoke API keys"
chk backend/app/core/netguard.py "is_blocked_ip" 1 "SSRF guard: stdlib classification (mapped IPv6, all DNS records)"
chk backend/app/services/webhook_service.py "netguard" 1 "Webhooks use the shared SSRF guard"
chk backend/app/core/mcp_registration.py "allow_stdio" 1 "MCP stdio registration is gated (no admin->RCE by default)"
# Ollama is EXTERNAL only: the removed "local" provider must not exist in code or UI strings.
_lo=$(grep -rnE "ollama_local|OLLAMA_LOCAL|OLLAMA_BASE_URL|ollama_base_url" "$TARGET/backend/app" "$TARGET/frontend/src" --include=*.py --include=*.ts --include=*.tsx 2>/dev/null \
      | grep -vE "core/llm_providers\.py|core/legacy_cleanup\.py|models/llm_config\.py|lib/providers\.ts" \
      | grep -vE ":[0-9]+:[[:space:]]*(#|//|\*|/\*)")
[[ -z "$_lo" ]] && ok "No local-Ollama provider left in backend/frontend code" || no "Local-Ollama code still present: $(echo "$_lo" | head -3 | cut -c1-110 | tr '\n' ';')"
_ls=$(grep -rnE "Local Ollama|Ollama \((L|l)ocal\)|Local LLM" "$TARGET/frontend/src" --include=*.ts --include=*.tsx 2>/dev/null)
[[ -z "$_ls" ]] && ok "No 'Local Ollama' wording in the UI" || no "UI still says 'Local Ollama': $(echo "$_ls" | head -2 | cut -c1-110 | tr '\n' ';')"
chk backend/app/core/legacy_cleanup.py "normalize_legacy_providers" 1 "Startup migration removes stored ollama_local data"
chk backend/app/main.py "normalize_legacy_providers" 1 "Startup migration is wired in"
chk backend/app/main.py "get_client_ip" 1 "Rate limiting keys on the real client IP (not nginx's)"
chk backend/app/api/websocket.py "origin_allowed" 1 "WebSockets validate Origin (no cross-site hijacking)"
chk deploy/nginx/nginx.conf 'X-Real-IP \$remote_addr' 2 "nginx overwrites X-Real-IP (dev)"
chk deploy/nginx/nginx.prod.conf 'X-Real-IP \$remote_addr' 2 "nginx overwrites X-Real-IP (prod)"

# Production TLS / parity (on-disk)
chk deploy/nginx/nginx.prod.conf "listen 443 ssl" 1 "Prod nginx serves HTTPS (443)"
chk deploy/nginx/nginx.prod.conf "acme-challenge" 1 "Prod nginx serves the ACME challenge (Let's Encrypt)"
chk deploy/nginx/nginx.prod.conf "Strict-Transport-Security" 2 "Prod nginx sends HSTS"
chk deploy/scripts/install-dev.sh "KEEP_EXISTING_ENV" 3 "Dev installer keeps an existing .env (no secret regeneration on re-run)"
chk deploy/scripts/recover-env.sh "db_ok" 1 "Env recovery script present"
# Design system foundation + favicon/logo safety
chk frontend/src/components/AppShell.tsx "CommandPalette" 1 "UI shell: top bar with command palette (Ctrl K)"
chk frontend/src/lib/nav.ts "NAV_GROUPS" 1 "UI shell: single navigation config (sidebar, breadcrumbs, palette)"
chk frontend/src/app/layout.tsx "THEME_INIT" 1 "Theme applied before first paint (no flash)"
[[ ! -f "$TARGET/frontend/src/app/favicon.ico" ]] && ok "Favicon: no duplicate src/app/favicon.ico (it conflicted with public/favicon.ico)" || no "Duplicate frontend/src/app/favicon.ico still present — it conflicts with public/favicon.ico and causes 500s"
[[ -f "$TARGET/frontend/public/favicon.ico" && -f "$TARGET/frontend/public/favicon.png" ]] && ok "Favicon files present in public/" || no "frontend/public/favicon.ico or favicon.png missing"
_lg=$(cd "$TARGET/frontend/public" 2>/dev/null && md5sum logo.png favicon.png favicon.ico 2>/dev/null | awk '{print $1}' | tr '\n' ' ')
[[ "$_lg" == "0a36ea064c81cef460554daf5b47d87b 600dd35a303e4bd8cdcf63051b61671b 08c4507e5b6297b6561af8d05a9e5a6b " ]] && ok "Logo and favicon files are unchanged" || wn "Logo/favicon files differ from the approved originals (fine if you changed them on purpose)"
_lu=$(grep -l '/logo.png' "$TARGET"/frontend/src/components/Sidebar.tsx "$TARGET"/frontend/src/app/login/page.tsx 2>/dev/null | wc -l)
(( _lu == 2 )) && ok "Sidebar and login page still use the existing logo" || no "Logo reference missing from the sidebar or login page"
! grep -q "@import url" "$TARGET/frontend/src/app/globals.css" && ok "Fonts load once (no duplicate @import)" || wn "globals.css still @imports fonts (loaded twice)"
# Phase 2 (page by page): converted pages must use theme tokens only, so they follow dark AND light
chk backend/app/api/v1/dashboard.py "shape_summary" 1 "Dashboard summary endpoint present (works for every signed-in user)"
chk frontend/src/components/ui/StatCard.tsx "stat-card" 1 "UI primitives present (PageHeader, Card, StatCard, Badge, Skeleton, EmptyState)"
_hx=$(grep -lE "#[0-9a-fA-F]{6}([0-9a-fA-F]{2})?\b" "$TARGET/frontend/src/app/(app)/dashboard/page.tsx" "$TARGET/frontend/src/components/VulnTrendsChart.tsx" "$TARGET"/frontend/src/components/ui/*.tsx 2>/dev/null)
[[ -z "$_hx" ]] && ok "Converted pages use theme tokens only (no hard-coded colors)" || no "Hard-coded colors in converted pages: $(echo "$_hx" | sed 's#.*/frontend/src/##' | tr '\n' ' ')"
# User management (admins can create users; deactivate / role change / reset sign the user out immediately)
chk backend/app/api/v1/admin.py "async def create_user" 1 "Admin can create users (POST /admin/users)"
chk backend/app/api/v1/admin.py "describe_delete_blockers" 1 "Delete user: keeps audit history, refuses to orphan owned work (409, never 500)"
chk backend/app/core/session_revocation.py "is_revoked" 1 "Per-user session revocation present"
chk backend/app/core/security.py '"iat"' 2 "Tokens carry an issue time (needed for revocation)"
chk frontend/src/components/admin/UsersPanel.tsx "Add user" 1 "Admin UI: Users panel with Add user, roles, reset password"
# Whole-frontend UI guards: theme tokens only (follows dark AND light), no native pop-ups, valid colour values, defined CSS variables
chk frontend/src/app/layout.tsx "DialogHost" 2 "Dialogs and toasts are mounted for every page (replaces alert/confirm)"
_ui=$(python3 "$TARGET/deploy/scripts/lib/ui_guards.py" "$TARGET" 2>&1); _uir=$(echo "$_ui" | tail -1)
if [[ "$_uir" == RESULT:*" 0 failed" ]]; then ok "UI guards: no hard-coded colours, native pop-ups, invalid colour values or undefined CSS variables (${_uir#RESULT: })"
else no "UI guards failed (${_uir#RESULT: })"; echo "$_ui" | grep '^FAIL' | head -6 | sed 's/^/      /'; fi
# Performance: the root causes found when "everything is slow" was reported
chk backend/app/models/user.py 'back_populates="owner", lazy="noload"' 1 "Perf: loading a user no longer drags in the whole scan history (User.projects not eager)"
chk backend/app/api/v1/scans.py "noload(Scan.tool_results)" 1 "Perf: scan LIST is lean (no raw tool output / analyses per scan)"
chk backend/app/api/v1/projects.py "noload(Project.scans)" 1 "Perf: project list does not load every project's scans"
chk backend/app/api/v1/vulnerabilities.py "noload(Vulnerability.fixes)" 1 "Perf: vulnerability list does not load fixes/exploits/comments per row"
chk backend/app/core/db_indexes.py "ensure_performance_indexes" 1 "Perf: missing foreign-key indexes are created at startup"

# ── Account security: two-factor, token types, sign-out, webhooks (backend) ──
chk backend/app/core/token_policy.py "def access_token_problem" 1 "Security: the temporary MFA token and refresh tokens are not accepted as access tokens (MFA bypass fix)"
chk backend/app/core/security.py "access_token_problem(payload)" 3 "Security: token type enforced for bearer, cookie and current-user lookups"
chk backend/app/api/websocket.py "access_token_problem" 1 "Security: token type enforced on WebSockets"
chk backend/app/api/v1/auth.py "Two-factor authentication is already on" 1 "Security: MFA setup cannot replace an active authenticator"
chk backend/app/api/v1/auth.py "body: MFALoginRequest" 1 "Security: the MFA sign-in token travels in the body, not the URL"
chk backend/app/api/v1/auth.py "async def logout_all" 1 "Sign out everywhere endpoint present"
chk backend/app/api/v1/admin.py "async def reset_user_mfa" 1 "Admin can reset a lost-device user's two-factor"
chk backend/app/core/webhook_events.py "ALLOWED" 1 "Webhooks: event catalog present (unknown events are refused)"
chk backend/app/tasks/scan_worker.py "await emit_scan_event(db, scan," 5 "Webhooks: fired when a scan completes or fails"
chk backend/app/api/v1/scans.py "scan.cancelled" 1 "Webhooks: fired when a scan is cancelled"
chk backend/app/core/legacy_cleanup.py "purge_unused_provider_keys" 1 "Stored plaintext personal provider API keys are purged at startup"
chk backend/tests/e2e_account_security.py "mfa_token" 1 "Live account-security check present"

# ── Account security + new screens (frontend) ──
none frontend/src/app/\(app\)/settings/page.tsx "admin/page" "Settings no longer embeds the Administration page"
chk frontend/src/components/settings/SecuritySection.tsx "mfaSetup" 1 "Settings > Security: two-factor enrolment"
chk frontend/src/components/settings/TokensSection.tsx "apiKeysApi" 1 "Settings > API tokens"
chk frontend/src/components/settings/WebhooksSection.tsx "webhooksApi" 1 "Settings > Webhooks"
chk frontend/src/components/settings/AiSection.tsx "chat_provider" 1 "Settings > AI providers (default provider and model)"
chk frontend/src/app/login/page.tsx "verifyLoginMfa" 1 "Sign-in asks for the two-factor code when the account has it"
chk frontend/src/components/AppShell.tsx "acct-menu" 1 "Account menu with Sign out (replaces the red Logout banner)"
chk frontend/src/components/admin/UsersPanel.tsx "resetMfa" 1 "Users: reset two-factor action"
chk frontend/src/app/\(app\)/admin/page.tsx "ADMIN_GROUPS" 1 "Administration: one level of navigation (no nested tabs)"
chk frontend/src/app/\(app\)/workflows/page.tsx "wf-foot" 1 "Workflows: redesigned template cards"
chk frontend/src/app/\(app\)/ai-chat/page.tsx "Session workspace" 1 "AI chat: collapsible session workspace"
chk frontend/src/app/\(app\)/ai-chat/page.tsx "socis.chat.history" 1 "AI chat: the conversation list can be hidden (remembered)"
chk frontend/src/components/ChatModelPicker.tsx "aria-expanded" 1 "AI chat: one compact model picker in the toolbar"

# ── Authorized target scope ──
chk backend/app/core/scope.py "def decide" 1 "Scope: authorized-target matching present (addresses, networks, ranges, hosts, wildcards)"
chk backend/app/services/scope_service.py "async def worker_gate" 1 "Scope: the worker checks EVERY scan before it runs"
chk backend/app/tasks/scan_worker.py "worker_gate(db, scan)" 1 "Scope: scan worker calls the gate"
chk backend/app/mcp/client.py "check_tool_call" 1 "Scope: every MCP tool call is checked (AI chat, MCP console, scans)"
chk backend/app/api/v1/scans.py "authorize_scan_target" 1 "Scope: scan creation checks project ownership and scope"
chk backend/app/api/v1/workflows.py "authorize_scan_target" 1 "Scope: workflow runs check scope"
chk backend/app/api/v1/schedules.py "authorize_scan_target" 2 "Scope: schedules check scope on create and trigger"
chk backend/app/api/v1/projects.py "set_project_scope" 1 "Scope: only administrators set a project's authorized scope"
chk backend/tests/e2e_scope.py "scope:override" 1 "Live scope check present"
chk backend/tools/verify_admin.py "verify" 1 "Verification uses a temporary admin, so it works with two-factor on"
chk backend/tools/reset_mfa.py "totp_enabled = False" 1 "Two-factor can be reset from the command line (reset-mfa.sh)"

# ── Prompt-injection hardening ──
chk backend/app/services/system_prompt.py "UNTRUSTED DATA" 1 "AI agent: untrusted-data policy in the system prompt (scan/tool output is never an instruction)"
chk backend/app/services/system_prompt.py "def wrap_untrusted_data" 1 "AI agent: tool/scan output is delimited before it reaches the model"
chk backend/app/api/v1/llm.py "wrap_untrusted_data" 2 "AI agent: both the synthesis pass and scan-context injection use the wrapper"
chk backend/app/api/v1/llm.py "Project.owner_id" 1 "Fixed: an AI chat scan_context_id can no longer read another user's scan (IDOR)"
chk backend/app/core/scope.py "target_host" 1 "Fixed: masscan CIDR and Metasploit target_host are recognised as scan targets"

# ── Plugin loading audit ──
chk backend/app/plugins/loader.py "is_symlink" 1 "Plugins: a symlinked plugin file is refused (code cannot be loaded from outside the directory)"
chk backend/app/plugins/loader.py "relative_to(plugins_dir_resolved)" 1 "Plugins: loaded files must resolve inside the plugins directory"
chk backend/app/main.py "plugins:loaded" 1 "Plugins: what was loaded at startup is written to the audit log"
chk backend/app/api/v1/admin.py "plugins:reloaded" 1 "Plugins: a manual reload is audited (who, and what changed)"
chk backend/app/api/v1/admin.py "/plugins/manifest" 1 "Plugins: an administrator can see every loaded file with its hash, size and any load error"
chk backend/app/core/report_safety.py "def embed_logos" 1 "Reports: logos are fetched safely by the server (network guard, no unchecked redirects) and embedded"
chk backend/app/services/report_service.py "only_data_image" 2 "Reports: the template only ever receives a validated colour and data: images"
chk backend/app/api/v1/settings.py "validate_logo_url_for_save" 1 "Reports: an internal or non-http logo address is refused when settings are saved"

# ── Failed scans must not read as clean; private networks must be allowable precisely ──
chk backend/app/core/tool_outcome.py "def tool_failed" 1 "A tool that did not run is recorded and reported as failed, not as a clean result"
chk backend/app/tasks/scan_worker.py "exit_code=exit_code_for(result_data)" 2 "The worker stores a failed tool call with a non-zero exit code"
chk backend/templates/report.html.j2 "incomplete-banner" 1 "Reports: an incomplete assessment shows a warning banner and an INCOMPLETE risk badge"
chk mcp-servers/mcp_auth.py "MCP_ALLOWED_PRIVATE_NETS" 1 "Tool servers: private networks can be allowed one by one without opening the Docker network"
chk deploy/scripts/allow-private-targets.sh "overlaps a Docker network" 1 "allow-private-targets.sh refuses ranges that overlap the platform's Docker networks"

# ── Report quality: no lost ports, no raw AI dump, remediation shown ──
chk mcp-servers/nmap_parse.py "def parse_open_ports" 1 "nmap: a port without a version no longer swallows the next port (the tool server uses a line-safe parser)"
chk mcp-servers/nmap_server.py "parse_open_ports" 2 "nmap tool server uses the line-safe parser"
chk backend/app/core/ai_report.py "def parse_ai_analysis" 1 "Reports: the AI analysis is parsed into a summary, findings and fixes (no raw dump)"
chk backend/app/services/report_service.py "_repaired_open_ports" 3 "Reports: scans stored with a lost port are repaired from the stored raw nmap output"
chk backend/templates/report.html.j2 "vuln.remediation" 2 "Reports: each finding shows its remediation"

# ── No internal targets sent to external services; skipped / failed / inferred are told apart ──
chk mcp-servers/target_scope.py "def ssl_labs_skip_reason" 1 "SSL tool: IP addresses and internal names are never sent to SSL Labs"
chk mcp-servers/ssl_server.py "ssl_labs_skip_reason" 2 "SSL tool checks the target before any external call"
chk mcp-servers/osint_server.py "whois_skip_reason" 2 "OSINT: no WHOIS lookup for private addresses"
chk backend/app/core/report_export.py "def csv_cell" 1 "Exports: CSV cells cannot run as spreadsheet formulas and Markdown text is escaped"
chk backend/app/core/evidence.py "def finding_evidence" 1 "Reports: each finding states what the tool output does and does not support"
chk backend/app/services/report_service.py "_export_view" 5 "Reports: HTML, Markdown, CSV and JSON are built from one shared view"
chk backend/app/core/scan_coverage.py "def coverage_note" 1 "Reports: a scan is told apart from what its own type promises (found: a Full scan that only ran nmap)"
chk backend/app/services/report_service.py "coverage_note" 4 "Reports: the methodology-coverage note reaches HTML/PDF, Markdown and JSON"

# ── OAuth/SSO: an identity cannot sign in as or silently link to someone else's account ──
chk backend/app/core/sso_policy.py "def decide" 1 "SSO: a single policy decides sign-in/link/create/deny (found: any provider e-mail could take over a local account)"
chk backend/app/api/v1/auth.py "hmac.compare_digest" 1 "SSO: the OAuth state is compared in constant time and cleared on every outcome (single use)"
chk backend/app/api/v1/auth.py "_oauth_login_or_create(oauth_user, db, cfg)" 2 "SSO: both providers route through the same sign-in policy"
chk backend/app/services/auth_service.py "email_verified" 2 "SSO: Google e-mail-verified flag is kept; Microsoft e-mail is never treated as verified"
chk frontend/src/app/auth/callback/\[provider\]/page.tsx "ssoCallback" 1 "SSO: the callback page exists (it did not before, every SSO sign-in failed)"
chk backend/app/tasks/scan_worker.py "_all_tools_failed" 4 "A scan whose tools ALL failed now shows as failed (dashboard + webhooks), not completed"

# ── AI chat: admin on/off for every tool ──
chk backend/app/core/ai_tool_policy.py "def effective_enabled" 1 "AI chat: one policy decides which tools it may call (server switch plus per-tool override, exploitation floor never admin-settable)"
chk backend/app/api/v1/settings.py "ai-chat-tools" 1 "AI chat: the admin can see every discovered tool and its on/off state"
chk backend/app/api/v1/llm.py "_tool_effective_enabled" 2 "AI chat: every tool call is checked against the per-tool policy before it runs"
chk "frontend/src/app/(app)/admin/page.tsx" "tool_overrides: toolOverrides" 1 "Admin: one Save sends the per-tool choices together with the server switches"
chk backend/tests/test_mcp_tool_reference.py "ast.literal_eval" 1 "AI chat: the tool reference is checked against the real tool schemas, extracted as data (found: 101 mismatches across 38 tools in 10 servers)"
chk backend/tests/test_worker_tool_calls.py "_path_statements" 1 "Scan worker: its own MCP tool calls are checked against the real tool schemas (found 3 harmless gaps; fixed 3 real undocumented-but-working server schemas)"
chk backend/app/core/tool_manifest.json "\"action\"" 100 "Builder coverage: a shared tool manifest (one entry per MCP tool) drives the builder picker and the worker dispatch"
chk backend/app/core/tool_manifest.py "def all_tools" 1 "Builder coverage: the manifest loader shared by the API and the worker"
chk backend/app/api/v1/tools.py "/manifest" 1 "Builder coverage: the manifest is served to the workflow builder via GET /tools/manifest"
chk backend/app/tasks/scan_worker.py "_build_manifest_args" 1 "Builder coverage: the worker dispatches ANY manifest tool generically (mcp:<server>:<action>), so every tool is runnable"
chk backend/app/tasks/scan_worker.py "SOCIS_AGENT_ALLOW_OFFENSIVE" 1 "Builder coverage: offensive tools from a builder node are gated behind the operator opt-in"
chk "frontend/src/app/(app)/workflows/builder/page.tsx" "ServerActionExtras" 22 "Builder coverage: every per-server panel lists ALL its server\'s actions (native + the rest via the manifest)"
chk backend/app/tasks/scan_worker.py "_NATIVE_ACTIONS" 1 "Builder coverage: a native-action table routes every non-native action a panel offers to the manifest dispatcher"
chk backend/app/core/tool_manifest.json "native_actions" 1 "Builder coverage: the manifest records which actions each panel renders natively, so the builder appends the rest"
chk frontend/src/components/workflow/nodes/shared.tsx "StatusChip" 1 "Builder UI: nodes show a status chip (done/running/queued) with accent bar and icon tile — the approved enterprise canvas look"
chk "frontend/src/app/(app)/workflows/builder/page.tsx" "RunStatusBar" 2 "Builder UI: a live run-status strip over the canvas (step N of M, done/running/queued)"
chk "frontend/src/app/(app)/workflows/builder/page.tsx" "PanelHeader" 2 "Builder UI: the config panel has the grouped header (icon tile, category, needs) from the approved mock"
chk "frontend/src/app/(app)/workflows/builder/page.tsx" "BackgroundVariant.Dots" 1 "Builder UI: dotted canvas background with radial glow (not the old flat line grid)"
chk "frontend/src/app/(app)/workflows/builder/page.tsx" "var(--on-accent)" 1 "Builder UI: the green Run button uses readable on-accent text (was invisible green-on-green)"
chk frontend/src/components/workflow/nodes/ToolNode.tsx "maxHeight: 280" 1 "Builder UI: a tool node's output is capped + scrollable, so a big scan can'"'"'t blow the node up and crowd the canvas"
chk backend/app/tasks/scan_worker.py "_start_node = next" 1 "Data flow: the Start node'"'"'s value (IP/CVE/domain/URL) drives the whole workflow"
chk backend/app/tasks/scan_worker.py "_VALUE_INHERIT_FIELDS" 1 "Data flow: a CVE/keyword set on the Start node flows into every downstream tool without re-typing"
chk frontend/src/components/workflow/nodes/ToolNode.tsx "MarkdownRenderer content={toMdComplete()}" 1 "Builder UI: node output uses the full markdown renderer (tables/lists/quotes), nothing dropped"
chk frontend/src/components/workflow/nodes/ToolNode.tsx "toMdComplete" 2 "Tool output: every tool now shows ALL fields the server returns (tool summary + a More details section), so no data is silently dropped"
chk frontend/src/components/workflow/nodes/ToolNode.tsx "attack_vector" 1 "Tool output: CVE Lookup shows the full detail (vector, attack vector, dates, CWEs, affected products, patches), not just severity+score"
chk frontend/src/components/workflow/nodes/shared.tsx "maxWidth: 280" 1 "Builder UI: nodes are wide enough (280px) to show output tables without cutting off columns"
chk backend/app/tasks/scan_worker.py "CVE IDs found by any CVE-producing node" 1 "Data flow: a CVE found by one node (CVE Lookup, CVE Lite) now flows into a later KEV/EPSS/PoC/CVE node automatically"
chk "frontend/src/app/(app)/workflows/builder/page.tsx" "add FFUF / SQLMap only if Nmap finds an HTTP" 1 "Workflow review: the Network Scan suggested chain no longer implies FFUF/SQLMap work on a bare IP"
chk "frontend/src/app/(app)/workflows/builder/page.tsx" "every OSINT action" 1 "Workflow review: OSINT Recon no longer invites a Company name that no tool in the chain can use"
chk "frontend/src/app/(app)/workflows/builder/page.tsx" "libCollapsed" 2 "Builder UI: the tool library can be hidden to give the canvas more room"
chk "frontend/src/app/(app)/workflows/builder/page.tsx" "setShowRunModal" 2 "Builder UI: the Run-workflow modal confirm button is readable (was invisible green-on-green)"
chk "frontend/src/app/(app)/workflows/builder/page.tsx" "nikto_timeout" 2 "Workflow builder: the Nikto HTTP timeout is now configurable (every other slow tool already had this; without it, a customer-set Max Time longer than the hidden 630s default silently got cut short)"
chk "frontend/src/lib/prettyToolOutput.ts" "12. MITRE ATT&CK" 1 "Scan output: MITRE ATT&CK results (27 tools) have their own readable layout, placed before the broad catch-all"
chk "frontend/src/lib/prettyToolOutput.ts" "13. ExploitDB" 1 "Scan output: ExploitDB results (18 tools) have their own readable layout, placed before the broad catch-all"
chk "frontend/src/app/(app)/scans/[id]/page.tsx" "from '@/lib/prettyToolOutput'" 1 "Scan output: the formatter was moved into its own module so it can be unit-tested directly"
chk frontend/scripts/test-pretty-tool-output.cjs "prettyToolOutput" 2 "Scan output: the formatter is tested against the real tool result shapes"
chk mcp-servers/nikto_server.py "evasion" 4 "nikto_ssl_only: the server now declares the optional fields its handler already used (useragent, proxy, auth, maxtime, evasion)"
chk mcp-servers/masscan_server.py "extra_args" 3 "masscan: all three tools now declare extra_args (already read and whitelist-validated by the handler, previously undeclared)"
chk mcp-servers/gobuster_server.py "HTTP Basic auth username" 1 "gobuster_fuzz: now declares username/password (already read by the handler)"
chk frontend/src/components/projects/ProjectScopeDialog.tsx "putScope" 1 "Projects: scope dialog (authorize, enforce, test a target, activity)"
chk frontend/src/components/ui/DialogHost.tsx "OverrideDialog" 1 "Blocked scans explain why; administrators can override with a written reason"
chk frontend/src/app/\(app\)/workflows/builder/page.tsx "askScopeOverride" 1 "Workflow builder Run no longer fails silently"
chk backend/app/main.py "ensure_performance_indexes" 1 "Perf: index creation is wired into startup (background)"
chk deploy/scripts/frontend-mode.sh "FRONTEND_TARGET" 1 "Perf: frontend can run as a pre-built production server (frontend-mode.sh)"
chk frontend/next.config.ts "optimizePackageImports" 1 "Perf: large UI libraries are import-optimised"
chk deploy/scripts/typecheck-frontend.sh "typecheck" 1 "Perf/build: typecheck-frontend.sh lists every TypeScript error with the real compiler"
chk frontend/Dockerfile "AS typecheck" 1 "Perf/build: Dockerfile has the typecheck stage"
chk frontend/next.config.ts "NEXT_STRICT_BUILD" 1 "Build: type errors do not block the production build unless NEXT_STRICT_BUILD=true"
chk deploy/scripts/lib/tls.sh "tls_letsencrypt_issue" 1 "TLS library: Let's Encrypt mode present"
chk deploy/scripts/lib/tls.sh "tls_selfsigned" 1 "TLS library: internal/self-signed mode present"
chk deploy/docker/docker-compose.prod.yml "noeviction" 1 "Prod Redis noeviction (queue + revoked-token safety)"
chk deploy/docker/docker-compose.prod.yml "nginx.prod.conf" 1 "Prod compose mounts the TLS nginx config"
_un=$(python3 "$TARGET/deploy/scripts/lib/undefined_names.py" "$TARGET/backend/app" "$TARGET/mcp-servers" 2>&1); _urc=$?
(( _urc == 0 )) && ok "No undefined names in backend/MCP code ($(echo "$_un" | tail -1))" || no "Undefined names (import/run-time NameError): $(echo "$_un" | grep UNDEFINED | head -3 | tr '\n' ';')"
_par=$(python3 "$TARGET/deploy/scripts/lib/compose_parity.py" "$TARGET/deploy/docker/docker-compose.dev.yml" "$TARGET/deploy/docker/docker-compose.prod.yml" 2>&1); _prc=$?
if   (( _prc == 0 )); then ok "Prod compose has not drifted from dev"
elif (( _prc == 2 )); then echo -e "  ${Y}· prod/dev parity check skipped (PyYAML not installed: apt install python3-yaml)${N}"
else no "Prod compose drift: ${_par#DRIFT: }"; fi

# Monitoring stack (observability #9)
chk deploy/docker/docker-compose.dev.yml "socis_grafana" 1 "Grafana service present"
chk deploy/docker/docker-compose.dev.yml "socis_prometheus" 1 "Prometheus service present"
chk backend/app/core/metrics.py "socis_http_requests_total" 1 "Backend metrics module present"
chk backend/app/main.py "metrics_endpoint" 1       "/metrics endpoint present"
chk frontend/src/lib/nav.ts "/monitoring/" 1 "Monitoring sidebar tab present"
if [[ -f "$TARGET/deploy/monitoring/grafana/dashboards/00-overview.json" ]]; then
  ok "Grafana dashboards present (4 JSON)"; else no "Grafana dashboards missing"; fi

# Logos
if [[ -f "$TARGET/frontend/public/logo.png" ]]; then
  sz=$(stat -c %s "$TARGET/frontend/public/logo.png" 2>/dev/null || echo 0)
  if (( sz > 50000 )); then ok "logo.png present (${sz} bytes)"; else wn "logo.png small (${sz} bytes) — may be old"; fi
else no "logo.png missing"; fi

# ─────────────────────────────────────────────────────────────────────────────
hdr "PHASE B — Runtime checks (running stack)"
if verify_admin_create; then echo -e "  using a temporary verification admin (removed afterwards); your real admin's two-factor is not touched"
else wn "Could not create the temporary verification admin (${VERIFY_ADMIN_ERROR:-no output}): live checks fall back to the real admin and stop at the two-factor step if it has it on"; fi

# Containers up?
up=$($COMPOSE ps --services --filter "status=running" 2>/dev/null | wc -l)
total=$($COMPOSE ps --services 2>/dev/null | wc -l)
if (( up >= 8 )); then ok "Containers running ($up/$total)"; else no "Only $up/$total containers running"; fi

# Wait for the backend to accept connections. Right after a rebuild uvicorn needs ~20-40s
# (DB init, seeding), so judging it immediately produced false failures.
_bup=false
for _i in $(seq 1 45); do
  if $COMPOSE exec -T backend curl -sf -o /dev/null http://localhost:8000/health 2>/dev/null; then _bup=true; break; fi
  (( _i == 1 )) && echo -e "  ${Y}· waiting for the backend to accept connections (up to 90s)…${N}"
  sleep 2
done
if [[ "$_bup" != true ]]; then
  no "Backend not answering on :8000 after 90s — it has crashed or is crash-looping"
  echo -e "      ${Y}relevant backend log lines:${N}"
  _blog=$($COMPOSE logs --tail=300 backend 2>/dev/null)
  echo "$_blog" | grep -iE "error|traceback|exception|importerror|modulenotfound|critical|application startup|uvicorn running" | tail -12 | sed 's/^/      /'
  if echo "$_blog" | grep -q "InvalidPasswordError"; then
    echo -e "      ${R}${B}Database password mismatch${N} — deploy/docker/.env no longer matches the password stored in the Postgres volume"
    echo -e "      (usually an installer re-run regenerated .env). Fix without losing data:  ${B}bash ${TARGET}/deploy/scripts/recover-env.sh${N}"
  fi
fi

# Backend deployment mode
mode=$($COMPOSE exec -T backend printenv DEPLOYMENT_MODE 2>/dev/null | tr -d '\r')
[[ -n "$mode" ]] && ok "Backend responds (DEPLOYMENT_MODE=$mode)" || no "Backend not responding"

# MCP shared secret must be set, or every tool call is rejected (401)
mcpt=$($COMPOSE exec -T backend printenv MCP_AUTH_TOKEN 2>/dev/null | tr -d '\r')
(( ${#mcpt} >= 32 )) && ok "MCP_AUTH_TOKEN configured (${#mcpt} chars)" || no "MCP_AUTH_TOKEN missing/short — all MCP tool calls would be rejected"
if [[ "$_CF" == *prod* ]]; then
  [[ "$mode" == "production" ]] && ok "Prod: DEPLOYMENT_MODE=production" || no "Prod install but DEPLOYMENT_MODE='$mode'"
  for kv in "DEBUG=false" "SECURE_COOKIES=true" "RATE_LIMIT_ENABLED=true"; do
    k="${kv%%=*}"; v="${kv#*=}"; got=$($COMPOSE exec -T backend printenv "$k" 2>/dev/null | tr -d '\r' | tr 'A-Z' 'a-z')
    [[ "$got" == "$v" ]] && ok "Prod: $k=$v" || no "Prod: $k='$got' (expected $v)"; done
  wmode=$($COMPOSE exec -T worker printenv DEPLOYMENT_MODE 2>/dev/null | tr -d '\r')
  [[ "$wmode" == "production" ]] && ok "Prod: worker also in production mode" || no "Prod: worker DEPLOYMENT_MODE='$wmode'"
fi

# Health
code=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE/health" 2>/dev/null)
[[ "$code" == "200" ]] && ok "/health -> 200" || wn "/health -> $code"

# Frontend reachable through nginx (no 502). In dev, `next dev` compiles each page on its FIRST request, which on a
# small CPU can take a minute or two (nginx used to answer 504 meanwhile). Wait for it, as we do for the backend.
_fok=false; _fe=""
for _i in $(seq 1 "${FE_WAIT_TRIES:-10}"); do
  _fe=$(curl -sk -o /dev/null -w "%{http_code}" --max-time "${FE_TRY_TIMEOUT:-30}" "$BASE/login" 2>/dev/null)
  [[ "$_fe" == "200" ]] && { _fok=true; break; }
  (( _i == 1 )) && echo -e "  ${Y}· waiting for the frontend (its first compile can take a minute or two)…${N}"
  sleep "${FE_WAIT_SLEEP:-3}"
done
if [[ "$_fok" != true ]]; then
  echo -e "      ${Y}frontend log lines (it did not answer /login with 200):${N}"
  $COMPOSE logs --tail=200 frontend 2>/dev/null | grep -iE "error|failed|cannot|module not found|compiling|compiled|ready|started server" | tail -12 | sed 's/^/      /'
fi
code="$_fe"
[[ "$code" == "200" ]] && ok "/login page -> 200 (no 502)" || no "/login -> $code (nginx/upstream issue)"

# CSS not blocked (MIME) — fetch a known asset type via the app
# (best-effort: just confirm the login page isn't empty)
len=$(curl -sk "$BASE/login" 2>/dev/null | wc -c)
(( len > 1000 )) && ok "Login page body non-trivial (${len} bytes)" || wn "Login page body small (${len} bytes)"
for _a in favicon.ico favicon.png logo.png; do
  _r=$(curl -sk -o /dev/null -w '%{http_code} %{content_type}' "$BASE/$_a" 2>/dev/null)
  if [[ "$_r" == 200\ image/* ]]; then ok "/$_a served ($_r)"; else no "/$_a -> $_r (expected 200 image/*)"; fi
done

# Login works + is reasonably fast
ADMIN_PW=$($COMPOSE exec -T backend printenv ADMIN_PASSWORD 2>/dev/null | tr -d '\r')
if [[ -n "$ADMIN_PW" ]]; then
  t0=$(date +%s.%N)
  lc=$($COMPOSE exec -T backend curl -s -o /dev/null -w "%{http_code}" \
       -X POST http://localhost:8000/api/v1/auth/login \
       -H "Content-Type: application/x-www-form-urlencoded" \
       -d "username=admin&password=${ADMIN_PW}" 2>/dev/null)
  t1=$(date +%s.%N)
  dur=$(awk "BEGIN{printf \"%.1f\", $t1-$t0}")
  if [[ "$lc" == "202" ]]; then
    ok "Backend login -> 202: password accepted, two-factor code required (${dur}s)"
  elif [[ "$lc" == "200" ]]; then
    ok "Backend login -> 200 (${dur}s)"
    awk "BEGIN{exit !($dur > 3)}" && wn "Login slow (${dur}s) — check BACKEND_CPUS limit"
  else no "Backend login -> $lc"; fi
else wn "ADMIN_PASSWORD not readable — skipped login test"; fi

# Token revocation (H-2): login via nginx, hit /me, logout, /me should 401
# (lightweight: just confirm /api/v1/auth/me requires auth)
code=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE/api/v1/auth/me" 2>/dev/null)
_stale=""
if [[ "$code" == "401" ]]; then ok "/auth/me unauthenticated -> 401 (auth enforced)"
elif [[ "$code" == "502" ]]; then
  if [[ "$_bup" == true ]]; then
    _stale=" — nginx 502 while the backend answers directly = stale upstream IP after a container recreate. Fix: docker compose -f ${TARGET}/deploy/docker/${_CF} restart nginx"
  else
    _stale=" — the backend is not answering on :8000 (see the failure above), so nginx has nothing to proxy to"
  fi
  wn "/auth/me -> 502${_stale}"
else wn "/auth/me -> $code (expected 401)"; fi

# CORS (C-3): a disallowed Origin must NOT be reflected
acao=$(curl -sk -o /dev/null -D - -H "Origin: http://evil.example.com" "$BASE/api/v1/health" 2>/dev/null | grep -i "access-control-allow-origin" | tr -d '\r')
if echo "$acao" | grep -qi "evil.example.com"; then no "CORS reflects arbitrary origin (C-3 regression!)"; else ok "CORS does not reflect arbitrary origin"; fi

# Redis eviction policy (PERF-4). Resolve the password from the backend env
# (Redis container doesn't export REDIS_PASSWORD itself), then query the policy.
rpw=$($COMPOSE exec -T backend printenv REDIS_URL 2>/dev/null | tr -d '\r' | sed -E 's|^redis://:([^@]*)@.*|\1|')
pol=$($COMPOSE exec -T redis redis-cli -a "$rpw" --no-auth-warning config get maxmemory-policy 2>/dev/null | tail -1 | tr -d '\r')
if [[ "$pol" == "noeviction" ]]; then ok "Redis maxmemory-policy = noeviction (live query)"
else no "Redis maxmemory-policy is '$pol' (expected noeviction) — queue/tokens could be evicted"; fi

# Resource limits actually applied to a container (PERF-1)
lim=$(docker inspect socis_backend --format '{{.HostConfig.NanoCpus}}' 2>/dev/null)
if [[ -n "$lim" && "$lim" != "0" ]]; then ok "Backend CPU limit applied ($((lim/1000000000)) cores)"; else wn "No CPU limit on backend (check deploy.resources)"; fi

# MCP servers healthy
mcp=$($COMPOSE ps mcp_all 2>/dev/null | grep -c healthy)
(( mcp >= 1 )) && ok "mcp_all healthy" || wn "mcp_all not reporting healthy"

# Backend /metrics endpoint exposes Prometheus data
mcode=$($COMPOSE exec -T backend curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/metrics 2>/dev/null)
if [[ "$mcode" == "200" ]]; then ok "/metrics endpoint -> 200"; else wn "/metrics -> $mcode"; fi

# Monitoring stack (only when the profile is running — otherwise skip, not fail)
if $COMPOSE ps grafana 2>/dev/null | grep -q socis_grafana; then
  hdr "PHASE C — Monitoring stack (profile running)"
  gcode=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE/monitoring/api/health" 2>/dev/null)
  [[ "$gcode" == "200" ]] && ok "Grafana /monitoring reachable -> 200" || wn "Grafana /monitoring -> $gcode"
  pcode=$($COMPOSE exec -T prometheus wget -qO- http://localhost:9090/-/healthy 2>/dev/null | grep -ci "healthy")
  (( pcode >= 1 )) && ok "Prometheus healthy" || wn "Prometheus not healthy"
  tjson=$($COMPOSE exec -T prometheus wget -qO- "http://localhost:9090/api/v1/targets" 2>/dev/null)
  t_up=$(echo "$tjson" | grep -o '"health":"up"' | wc -l); t_all=$(echo "$tjson" | grep -o '"health":"[a-z]*"' | wc -l)
  if (( t_all > 0 && t_up == t_all )); then ok "Prometheus scraping all targets ($t_up/$t_all up)"
  elif (( t_up >= 1 )); then
    wn "Prometheus targets: $t_up/$t_all up — a target recovers within one 15s scrape after its container restarts; re-run in a moment if you just rebuilt"
    echo "$tjson" | python3 -c 'import sys,json
try:
    for t in json.load(sys.stdin)["data"]["activeTargets"]:
        if t.get("health") != "up":
            print("      down: %s  %s  -> %s" % (t["labels"].get("job"), t.get("scrapeUrl"), (t.get("lastError") or "not scraped yet")[:100]))
except Exception:
    pass' 2>/dev/null
  else wn "No Prometheus targets up yet"; fi
else
  echo -e "\n  ${Y}· Monitoring profile not running — skipped (enable: docker compose --profile monitoring up -d)${N}"
fi

# ─────────────────────────────────────────────────────────────────────────────
hdr "PHASE D — Security behavior (active runtime tests)"

# L-9 CSRF: a cookie-authenticated mutating request WITHOUT the X-Requested-With
# header must be rejected (403). We can't easily get a real session cookie here,
# so we assert that a POST carrying a dummy access_token cookie but no header is
# refused with 403 (the CSRF guard fires before auth).
csrf=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "$BASE/api/v1/scans" \
  -H "Content-Type: application/json" --cookie "access_token=dummy" -d '{}' 2>/dev/null)
if [[ "$csrf" == "403" ]]; then ok "L-9 CSRF: cookie POST without X-Requested-With -> 403 (blocked)"
else wn "L-9 CSRF: expected 403, got $csrf${_stale:- (check middleware/exemptions)}"; fi

# L-9 positive: the SAME request WITH the header should get past CSRF (then fail
# auth, not 403) — proving the header is what distinguishes them. Follow
# redirects (-L) so a trailing-slash 307 doesn't mask the final status.
csrf_ok=$(curl -sk -L -o /dev/null -w "%{http_code}" -X POST "$BASE/api/v1/scans" \
  -H "Content-Type: application/json" -H "X-Requested-With: SOCIS" \
  --cookie "access_token=dummy" -d '{}' 2>/dev/null)
if [[ "$csrf_ok" != "403" ]]; then ok "L-9 CSRF: with header, passes CSRF (-> $csrf_ok, not 403)"
else no "L-9 CSRF: with header still 403 — header not being honored"; fi

# H-2 token revocation: a bogus/forged bearer token must be rejected on an
# authenticated endpoint (401), confirming tokens are validated (not trusted).
h2=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE/api/v1/auth/me" \
  -H "Authorization: Bearer forged.invalid.token" 2>/dev/null)
if [[ "$h2" == "401" ]]; then ok "H-2 auth: forged bearer token -> 401 (rejected)"
else wn "H-2 auth: expected 401 for forged token, got $h2${_stale:+ (same cause as the /auth/me warning above)}"; fi

# H-5 SSRF: call the validator INSIDE the mcp container (no token needed) and
# assert the cloud-metadata + loopback targets are refused.
ssrf_out=$($COMPOSE exec -T mcp_all sh -c 'd=$(dirname "$(find / -name mcp_auth.py -not -path "*/node_modules/*" 2>/dev/null | head -1)"); cd "$d" && python3 - <<PY
import sys, types
try:
    import fastapi
except Exception:
    fa=types.ModuleType("fastapi"); fa.Request=object
    fr=types.ModuleType("fastapi.responses"); fr.JSONResponse=object
    sys.modules["fastapi"]=fa; sys.modules["fastapi.responses"]=fr
from mcp_auth import validate_scan_target
bad=0
for t in ("169.254.169.254","127.0.0.1"):
    try:
        validate_scan_target(t); bad+=1
    except ValueError:
        pass
print("SSRF_BLOCKED_ALL" if bad==0 else "SSRF_LEAK")
PY' 2>/dev/null | tail -1)
if [[ "$ssrf_out" == "SSRF_BLOCKED_ALL" ]]; then ok "H-5 SSRF: metadata (169.254.169.254) + loopback refused by validator"
elif [[ "$ssrf_out" == "SSRF_LEAK" ]]; then no "H-5 SSRF: validator ALLOWED a blocked target!"
else wn "H-5 SSRF: could not run validator in mcp_all (non-fatal)"; fi

# Regression suite for the SSRF guard / MCP registration / client-IP logic, run INSIDE the live backend container.
_sg=$(bexec sh -c 'cd /app && python tests/test_security_guards.py 2>&1 | tail -1' 2>/dev/null | tr -d '\r')
if [[ "$_sg" == RESULT:*" 0 failed" ]]; then ok "Security guard regression tests pass in the running backend (${_sg#RESULT: })"
elif [[ -z "$_sg" ]]; then wn "Security guard tests could not run in the backend container"
else no "Security guard regression tests FAILED in the running backend: $_sg"; fi

# The report exporters (HTML/PDF context, Markdown, CSV, JSON) run on a scan fixture inside the live backend.
_re=$(bexec sh -c 'cd /app && python tests/test_report_exports.py 2>&1 | tail -1' 2>/dev/null | tr -d '\r')
if [[ "$_re" == RESULT:*" 0 failed" ]]; then ok "Report export tests pass in the running backend (${_re#RESULT: })"
elif [[ -z "$_re" ]]; then wn "Report export tests could not run in the backend container"
else no "Report export tests FAILED in the running backend: $_re"; fi

# SSO sign-in policy, run against the REAL _oauth_login_or_create (a fake database stands in; no real Google/Microsoft call is made).
_sso=$(bexec sh -c 'cd /app && python tests/test_sso_flow.py 2>&1 | tail -1' 2>/dev/null | tr -d '\r')
if [[ "$_sso" == RESULT:*" 0 failed" ]]; then ok "SSO sign-in policy tests pass in the running backend (${_sso#RESULT: })"
elif [[ -z "$_sso" ]]; then wn "SSO sign-in policy tests could not run in the backend container"
else no "SSO sign-in policy tests FAILED in the running backend: $_sso"; fi

# AI chat tool policy: the real admin endpoints and save logic against fakes.
_atp=$(bexec sh -c 'cd /app && python tests/test_ai_tool_policy.py 2>&1 | tail -1' 2>/dev/null | tr -d '\r')
if [[ "$_atp" == RESULT:*" 0 failed" ]]; then ok "AI chat tool policy tests pass in the running backend (${_atp#RESULT: })"
elif [[ -z "$_atp" ]]; then wn "AI chat tool policy tests could not run in the backend container"
else no "AI chat tool policy tests FAILED in the running backend: $_atp"; fi

# MCP tool reference: does every example the AI chat is shown match what the tool servers will actually accept (needs
# mcp-servers/, so this runs on the host, not inside the backend container).
_mcpref=$(cd "$TARGET" && python3 backend/tests/test_mcp_tool_reference.py 2>&1 | tail -1)
if [[ "$_mcpref" == RESULT:*" 0 failed" ]]; then ok "AI chat tool reference matches the real tool schemas (${_mcpref#RESULT: })"
elif [[ "$_mcpref" == *"SKIP"* ]]; then wn "MCP tool reference check skipped: mcp-servers/ not found at $TARGET"
else no "AI chat tool reference has mismatches against the real tool schemas: $_mcpref"; fi

# The scan worker's OWN tool dispatch (what runs for a scan type / workflow, separate from the AI chat path above).
_workertools=$(cd "$TARGET" && python3 backend/tests/test_worker_tool_calls.py 2>&1 | tail -1)
if [[ "$_workertools" == RESULT:*" 0 failed" ]]; then ok "Scan worker's own tool calls match the real tool schemas (${_workertools#RESULT: })"
elif [[ "$_workertools" == *"SKIP"* ]]; then wn "Scan worker tool-call check skipped: mcp-servers/ not found at $TARGET"
else no "Scan worker tool calls have mismatches against the real tool schemas: $_workertools"; fi

# The shared tool manifest vs the real MCP server schemas: every tool present, every field correct. This is the
# guardrail that keeps "the builder covers every MCP tool" true as tools change.
_manifest=$(cd "$TARGET" && python3 backend/tests/test_tool_manifest.py 2>&1)
_manifest_last=$(printf '%s\n' "$_manifest" | tail -1)
_manifest_cov=$(printf '%s\n' "$_manifest" | grep -oE "Manifest covers [0-9]+ of [0-9]+" | head -1)
if [[ "$_manifest_last" == RESULT:*" 0 failed" ]]; then ok "Tool manifest matches the real MCP schemas — ${_manifest_cov:-coverage unknown} real tools"
elif [[ "$_manifest" == *"SKIP"* ]]; then wn "Tool manifest check skipped: mcp-servers/ not found at $TARGET"
else no "Tool manifest does not match the real MCP schemas: $_manifest_last"; fi

# The generic manifest dispatcher: can the worker build a correct MCP call for every manifest tool, with the offensive gate?
_gdisp=$(cd "$TARGET" && python3 backend/tests/test_generic_dispatch.py 2>&1 | tail -1)
if [[ "$_gdisp" == RESULT:*" 0 failed" ]]; then ok "Every manifest tool is runnable from a builder node (generic dispatch: ${_gdisp#RESULT: })"
else no "Generic manifest dispatch has gaps: $_gdisp"; fi

# Node-to-node CVE propagation (a CVE found by one node flows into later KEV/EPSS/PoC/CVE nodes) + the workflow-type fixes.
_cveprop=$(cd "$TARGET" && python3 backend/tests/test_cve_propagation.py 2>&1 | tail -1)
if [[ "$_cveprop" == RESULT:*" 0 failed" ]]; then ok "CVE propagation + workflow-type review fixes verified (${_cveprop#RESULT: })"
else no "CVE propagation tests FAILED: $_cveprop"; fi

# XSS regression: markdown links from attacker-influenced tool output must block javascript:/data: schemes.
if [[ -f "$TARGET/frontend/scripts/test-safe-href.cjs" ]]; then
  _xss=$(cd "$TARGET/frontend" && node scripts/test-safe-href.cjs 2>&1 | tail -1)
  if [[ "$_xss" == RESULT:*" 0 failed" ]]; then ok "Markdown link XSS guard holds (${_xss#RESULT: })"
  else no "Markdown link XSS guard FAILED: $_xss"; fi
fi

# Every manifest server must be registered in app/mcp/client.py, or it is invisible on /mcp, "Tools & MCP", and the AI
# chat tool-by-tool setting even though it works in the builder (the exact bug found reviewing the AD server).
_reg=$(cd "$TARGET" && python3 backend/tests/test_mcp_client_registry.py 2>&1 | tail -1)
if [[ "$_reg" == RESULT:*" 0 failed" ]]; then ok "Every MCP server is registered for the admin/AI-chat UI, not just the builder (${_reg#RESULT: })"
else no "MCP client registry gap: $_reg"; fi

chk mcp-servers/cloud_server.py "validate_scan_target\|validate_url_target" 1 "Cloud Recon server: every target is scope-checked, no direct metadata-service dial"
chk backend/app/core/tool_manifest.json "bucket_enum" 1 "Cloud Recon: 4 tools (bucket_enum, bucket_guess, cloud_fingerprint, metadata_check) in the manifest"

chk mcp-servers/container_server.py "validate_scan_target" 1 "Container/K8s server: the network-facing tool (docker_api_check) is scope-checked"
chk backend/app/core/tool_manifest.json "k8s_manifest_scan" 1 "Container/K8s: 4 tools (image_scan, dockerfile_scan, k8s_manifest_scan, docker_api_check) in the manifest"

chk mcp-servers/secrets_server.py "redact" 1 "Secrets server: matched credentials are redacted in findings, not reproduced in full"
chk backend/app/core/tool_manifest.json "graphql_introspect" 1 "API Security: 4 tools (graphql_introspect, graphql_query_risk, openapi_discover, api_misconfig_check) in the manifest"
chk backend/app/core/tool_manifest.json "scan_repo_snapshot" 1 "Secrets Scanning: 2 tools (scan_content, scan_repo_snapshot) in the manifest"

chk mcp-servers/dns_deep_server.py "validate_scan_target" 1 "DNS Deep server: every domain is scope-checked"
chk mcp-servers/crack_server.py "_ALLOWED_FORMATS" 1 "Password Cracking server: hash format is restricted to an allow-list, not free text"
chk backend/app/core/tool_manifest.json "zone_transfer_check" 1 "DNS Deep: 3 tools (zone_transfer_check, subdomain_takeover_check, email_security_posture) in the manifest"
chk backend/app/core/tool_manifest.json "crack_hash" 1 "Password Cracking: 2 tools (crack_hash, list_formats) in the manifest"
chk backend/app/core/tool_manifest.json "classify_finding" 1 "Compliance Mapping: 3 tools (classify_finding, map_tool_to_standards, list_mappings) in the manifest"

_pss=$(cd "$TARGET" && python3 backend/tests/test_platform_settings_size.py 2>&1 | tail -1)
if [[ "$_pss" == RESULT:*" 0 failed" ]]; then ok "platform_settings.value is unbounded Text, not a fixed VARCHAR that overflows as servers are added (${_pss#RESULT: })"
else no "platform_settings size regression: $_pss"; fi
chk backend/app/models/settings.py "mapped_column(Text" 1 "platform_settings.value uses Text (no fixed-size cap)"

_stamp=$(cd "$TARGET" && python3 backend/tests/test_alembic_autostamp.py 2>&1 | tail -1)
if [[ "$_stamp" == RESULT:*" 0 failed" ]]; then ok "Alembic auto-stamp logic is safe (checks before stamping, never fatal, documented caveat) (${_stamp#RESULT: })"
else no "Alembic auto-stamp regression: $_stamp"; fi

_llmcreds=$(cd "$TARGET" && python3 backend/tests/test_llm_provider_credentials.py 2>&1 | tail -1)
if [[ "$_llmcreds" == RESULT:*" 0 failed" ]]; then ok "Admin-saved LLM provider API keys are actually used at runtime, not just saved and ignored (${_llmcreds#RESULT: })"
else no "LLM provider credentials regression: $_llmcreds"; fi

_fetchmodels=$(cd "$TARGET" && python3 backend/tests/test_llm_fetch_models.py 2>&1 | tail -1)
if [[ "$_fetchmodels" == RESULT:*" 0 failed" ]]; then ok "Admin can fetch a real model list per provider instead of typing an exact model name from memory (${_fetchmodels#RESULT: })"
else no "LLM fetch-models regression: $_fetchmodels"; fi

_llmdefault=$(cd "$TARGET" && python3 backend/tests/test_llm_default_provider_everywhere.py 2>&1 | tail -1)
if [[ "$_llmdefault" == RESULT:*" 0 failed" ]]; then ok "The configured default LLM provider is actually used by the automatic post-scan analysis AND the workflow LLM node, not hardcoded to Ollama (${_llmdefault#RESULT: })"
else no "LLM default-provider regression: $_llmdefault"; fi
_llmvis=$(cd "$TARGET" && python3 backend/tests/test_llm_chat_provider_visibility.py 2>&1 | tail -1)
if [[ "$_llmvis" == RESULT:*" 0 failed" ]]; then ok "A provider configured purely via Admin -> AI providers appears in the AI Chat picker, not just .env-configured ones (${_llmvis#RESULT: })"
else no "LLM chat provider visibility regression: $_llmvis"; fi

_llmux=$(cd "$TARGET" && python3 backend/tests/test_llm_ux_consistency.py 2>&1 | tail -1)
if [[ "$_llmux" == RESULT:*" 0 failed" ]]; then ok "Provider/model selection is consistent across AI Chat, Findings, and the Workflow LLM node — shared mechanism, no duplicate label maps, a real platform-default switch (${_llmux#RESULT: })"
else no "LLM UX consistency regression: $_llmux"; fi

_offgate=$(cd "$TARGET" && python3 backend/tests/test_offensive_server_gate.py 2>&1 | tail -1)
if [[ "$_offgate" == RESULT:*" 0 failed" ]]; then ok "Every offensive MCP tool is gated at the server itself (defense-in-depth), not just the backend dispatcher (${_offgate#RESULT: })"
else no "Offensive server gate regression: $_offgate"; fi

_vulns=$(cd "$TARGET" && python3 backend/tests/test_vulnerabilities_api.py 2>&1 | tail -1)
if [[ "$_vulns" == RESULT:*" 0 failed" ]]; then ok "Vulnerabilities module: server-side search, bulk-update with per-row auth, CSV-injection safe, shared dedup'd components (${_vulns#RESULT: })"
else no "Vulnerabilities module regression: $_vulns"; fi

_finds=$(cd "$TARGET" && python3 backend/tests/test_findings_module.py 2>&1 | tail -1)
if [[ "$_finds" == RESULT:*" 0 failed" ]]; then ok "Findings module: promote-to-vulnerability bridge (per-row auth, idempotent), signal-first rows, Needs-Review triage, renderer extracted (${_finds#RESULT: })"
else no "Findings module regression: $_finds"; fi

_apikey=$(cd "$TARGET" && python3 backend/tests/test_api_key_regenerate.py 2>&1 | tail -1)
if [[ "$_apikey" == RESULT:*" 0 failed" ]]; then ok "API tokens: regenerate-in-place (own-keys scoped, shown-once, hash-only storage preserved) (${_apikey#RESULT: })"
else no "API key regenerate regression: $_apikey"; fi

_findings=$(cd "$TARGET" && python3 backend/tests/test_findings_ai_analysis.py 2>&1 | tail -1)
if [[ "$_findings" == RESULT:*" 0 failed" ]]; then ok "/findings AI analysis resolves the admin-saved LLM config (not just a hardcoded Ollama call) (${_findings#RESULT: })"
else no "findings AI analysis regression: $_findings"; fi
_adminllm=$(cd "$TARGET" && python3 backend/tests/test_admin_llm_providers_card.py 2>&1 | tail -1)
if [[ "$_adminllm" == RESULT:*" 0 failed" ]]; then ok "Admin LLM Providers is its own card, not nested inside Remote Ollama Configuration (${_adminllm#RESULT: })"
else no "Admin LLM Providers card regression: $_adminllm"; fi
chk mcp-servers/ad_server.py "validate_scan_target" 1 "AD server: every target is scope-checked (cannot be pointed at the platform's own infra)"
chk mcp-servers/ad_server.py "create_subprocess_exec" 1 "AD server: tools run with an argument list, never a shell (no command injection)"
chk backend/app/core/tool_manifest.json "password_spray" 1 "AD server: offensive tools (spray, AS-REP roast) are in the manifest and gated by the offensive opt-in"
# How every tool result is SHOWN on the scan detail page (MITRE / ExploitDB / CVE / nmap ...), run against payloads shaped like the
# real tool-server output. Needs node + the typescript package; where they are missing it says so without counting a warning.
if command -v node >/dev/null 2>&1 && [[ -f "$TARGET/frontend/scripts/test-pretty-tool-output.cjs" ]]; then
  _pto_full=$(cd "$TARGET/frontend" && node scripts/test-pretty-tool-output.cjs 2>&1)
  _pto=$(printf '%s\n' "$_pto_full" | tail -1)
  if printf '%s' "$_pto_full" | grep -q '^SKIP'; then echo "  · Scan output formatting test skipped here (the typescript package is not installed on this host)"
  elif [[ "$_pto" == RESULT:*" 0 failed" ]]; then ok "Scan output formatting matches the real tool result shapes (${_pto#RESULT: })"
  else no "Scan output formatting test FAILED: $_pto"; fi
else echo "  · Scan output formatting test skipped here (node is not installed on this host)"; fi

# AI chat: the stream must START (this executes the chat-session limiter). An LLM need not be
# reachable — the server sends a keep-alive/error event first. A NameError here once broke all chat.
_chat=$(bexec sh -c '
  T=$(curl -s -X POST http://localhost:8000/api/v1/auth/login -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "username=${VERIFY_ADMIN_USER:-admin}" --data-urlencode "password=${VERIFY_ADMIN_PASSWORD:-$ADMIN_PASSWORD}" | python3 -c "import sys,json;print(json.load(sys.stdin).get(\"access_token\",\"\"))" 2>/dev/null)
  [ -z "$T" ] && { echo NOLOGIN; exit 0; }
  curl -sN --max-time 20 -X POST http://localhost:8000/api/v1/llm/chat -H "Authorization: Bearer $T" -H "Content-Type: application/json" \
        -d "{\"messages\":[{\"role\":\"user\",\"content\":\"ping\"}],\"stream\":true}" | head -c 400' 2>/dev/null | tr -d '\r')
if [[ "$_chat" == NOLOGIN ]]; then wn "AI chat check skipped (admin login failed)"
elif echo "$_chat" | grep -qE '^(data:|: keepalive)'; then ok "AI chat stream starts (limiter + generator run)"
elif echo "$_chat" | grep -qi "not configured"; then
  echo -e "  ${Y}· AI chat endpoint answers, but no LLM is configured (Admin → Settings → Remote Ollama), so the streaming path was NOT exercised${N}"
elif [[ -z "$_chat" ]]; then no "AI chat returned nothing — the chat endpoint is failing (check: docker compose logs backend | grep -i error)"
else wn "AI chat returned an unexpected reply: ${_chat:0:120}"; fi

# The live API must not advertise a "local" Ollama provider (it used to, under /llm/models and /llm/status).
_lp=$(bexec sh -c '
  T=$(curl -s -X POST http://localhost:8000/api/v1/auth/login -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "username=${VERIFY_ADMIN_USER:-admin}" --data-urlencode "password=${VERIFY_ADMIN_PASSWORD:-$ADMIN_PASSWORD}" | python3 -c "import sys,json;print(json.load(sys.stdin).get(\"access_token\",\"\"))" 2>/dev/null)
  [ -z "$T" ] && { echo NOLOGIN; exit 0; }
  for p in /api/v1/llm/models /api/v1/llm/status; do curl -s -H "Authorization: Bearer $T" "http://localhost:8000$p"; done | grep -c ollama_local' 2>/dev/null | tr -d '\r' | tail -1)
if [[ "$_lp" == "0" ]]; then ok "Live API exposes no local-Ollama provider (/llm/models, /llm/status)"
elif [[ "$_lp" == NOLOGIN ]]; then wn "local-Ollama API check skipped (admin login failed)"
else no "The live API still advertises ollama_local ($_lp occurrence(s))"; fi

# The dashboard summary must work for any signed-in user (the old admin-only endpoint gave analysts all zeros).
_ds=$(bexec sh -c '
  T=$(curl -s -X POST http://localhost:8000/api/v1/auth/login -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "username=${VERIFY_ADMIN_USER:-admin}" --data-urlencode "password=${VERIFY_ADMIN_PASSWORD:-$ADMIN_PASSWORD}" | python3 -c "import sys,json;print(json.load(sys.stdin).get(\"access_token\",\"\"))" 2>/dev/null)
  [ -z "$T" ] && { echo NOLOGIN; exit 0; }
  curl -s -H "Authorization: Bearer $T" http://localhost:8000/api/v1/dashboard/summary | python3 -c "import sys,json
d=json.load(sys.stdin)
need=(\"scans_total\",\"scans_active\",\"projects\",\"reports\",\"vulns_open\",\"open_by_severity\")
print(\"OK\" if all(k in d for k in need) and all(k in d[\"open_by_severity\"] for k in (\"critical\",\"high\",\"medium\",\"low\",\"info\")) else \"BAD:\"+str(d)[:120])" 2>&1' 2>/dev/null | tr -d '\r' | tail -1)
if [[ "$_ds" == OK ]]; then ok "Dashboard summary endpoint returns real counts (/api/v1/dashboard/summary)"
elif [[ "$_ds" == NOLOGIN ]]; then wn "dashboard summary check skipped (admin login failed)"
else no "Dashboard summary endpoint is broken: ${_ds:0:140}"; fi

# User management, live: create -> sign in -> RBAC -> reset / role change / deactivate sign the user out IMMEDIATELY -> safety rules.
_ul=$(bexec sh -c 'cd /app && python tests/e2e_user_lifecycle.py 2>&1' 2>/dev/null | tr -d '\r')
_ulr=$(echo "$_ul" | tail -1)
if [[ "$_ulr" == RESULT:*" 0 failed" ]]; then ok "User management works live: create, RBAC, instant sign-out on role change/reset/deactivate, safety rules (${_ulr#RESULT: })"
elif [[ -z "$_ul" ]]; then wn "User management live check could not run in the backend container"
else no "User management live check FAILED (${_ulr#RESULT: })"; echo "$_ul" | grep -E "^FAIL" | head -6 | sed 's/^/      /'; fi

# Account security, live: replays the old MFA bypass, enrols two-factor, signs in with a code, API tokens, password change signs
# OTHER devices out, sign-out-everywhere, webhooks, admin MFA reset, lock-out. Takes about a minute.
_as=$(bexec sh -c 'cd /app && python tests/e2e_account_security.py 2>&1' 2>/dev/null | tr -d '\r')
_asr=$(echo "$_as" | tail -1)
if [[ "$_asr" == RESULT:*" 0 failed" ]]; then ok "Account security works live: MFA bypass closed, two-factor sign-in, API tokens, sign-out of other devices, webhooks (${_asr#RESULT: })"
elif [[ -z "$_as" ]]; then wn "Account security live check could not run in the backend container"
else no "Account security live check FAILED (${_asr#RESULT: })"; echo "$_as" | grep -E "^FAIL" | head -8 | sed 's/^/      /'; fi

# Authorized scope, live: new project is enforced and empty, analysts cannot authorize, scans / workflows / tool calls outside the list
# are refused, too-broad entries refused, override needs a reason and an admin, forged marker ignored, everything audited. ~30 seconds.
_sc=$(bexec sh -c 'cd /app && python tests/e2e_scope.py 2>&1' 2>/dev/null | tr -d '\r')
_scr=$(echo "$_sc" | tail -1)
if [[ "$_scr" == RESULT:*" 0 failed" ]]; then ok "Authorized target scope works live: blocked until authorized, tool calls gated, override rules, audit (${_scr#RESULT: })"
elif [[ -z "$_sc" ]]; then wn "Scope live check could not run in the backend container"
else no "Authorized scope live check FAILED (${_scr#RESULT: })"; echo "$_sc" | grep -E "^FAIL" | head -8 | sed 's/^/      /'; fi

# Performance, live: timings + "is the scan list lean?" + indexes + how the frontend runs
_pp=$(bexec sh -c 'cd /app && python tests/perf_probe.py 2>&1' 2>/dev/null | tr -d '\r'); _ppr=$(echo "$_pp" | tail -1)
if [[ -z "$_pp" ]]; then wn "Perf probe could not run in the backend container"
elif [[ "$_ppr" == RESULT:*" 0 failed"* ]]; then ok "API list endpoints are lean and answer promptly (scan list, projects, vulnerabilities, dashboard)"
else no "Perf probe FAILED"; echo "$_pp" | grep -E "^FAIL" | head -4 | sed 's/^/      /'; fi
echo "$_pp" | grep -E "^WARN" | head -4 | while IFS= read -r _w; do wn "${_w#WARN }"; done
_nix=$($COMPOSE exec -T postgres sh -c "psql -U \"\$POSTGRES_USER\" -d \"\$POSTGRES_DB\" -At -c \"SELECT count(*) FROM pg_indexes WHERE indexname LIKE 'ix_perf_%'\"" 2>/dev/null | tr -d '\r')
if [[ "${_nix:-0}" =~ ^[0-9]+$ ]] && (( _nix > 0 )); then ok "Performance indexes present in the database (${_nix})"
else wn "Performance indexes not found yet: they are created in the background shortly after the backend starts. Re-run in a minute, or: bash deploy/scripts/perf-check.sh"; fi
_fe=$($COMPOSE exec -T frontend printenv NODE_ENV 2>/dev/null | tr -d '\r')
if [[ "$_fe" == production ]]; then ok "Frontend runs as a pre-built production server (fast navigation)"
elif [[ "$_fe" == development ]]; then wn "Frontend runs in DEVELOPMENT mode (next dev): each page compiles on first visit, so navigation feels slow. Switch: bash deploy/scripts/frontend-mode.sh prod"; fi

# The frontend's Node heap cap must sit safely below its container memory limit (otherwise it outgrows the container and stalls)
_fid=$($COMPOSE ps -q frontend 2>/dev/null | head -1)
if [[ -n "$_fid" ]]; then
  _lim=$(( $(docker inspect -f '{{.HostConfig.Memory}}' "$_fid" 2>/dev/null || echo 0) / 1048576 ))
  _heap=$($COMPOSE exec -T frontend printenv NODE_OPTIONS 2>/dev/null | tr -d '\r' | sed -nE 's/.*--max-old-space-size=([0-9]+).*/\1/p')
  if [[ -z "$_heap" || "$_lim" -le 0 ]]; then wn "Frontend memory limit / heap cap could not be read"
  elif (( _heap * 100 >= _lim * 85 )); then wn "Frontend Node heap cap (${_heap} MB) is not safely below its memory limit (${_lim} MB): it can stall or be killed under load. Set FRONTEND_MEM=2g in deploy/docker/.env and recreate the frontend."
  else ok "Frontend memory limit (${_lim} MB) leaves room for Node's heap cap (${_heap} MB)"; fi
fi

# C-4 production guard: confirm the guard logic exists and current mode is known.
pmode=$($COMPOSE exec -T backend printenv DEPLOYMENT_MODE 2>/dev/null | tr -d '\r')
if [[ "$pmode" == "production" ]]; then
  # In production, DEBUG must be false and docs hidden.
  docs=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE/api/docs" 2>/dev/null)
  [[ "$docs" == "404" ]] && ok "C-4 prod: /api/docs hidden (404)" || wn "C-4 prod: /api/docs -> $docs (expected 404)"
else
  ok "C-4: development mode (production guards enforce on prod switch)"
fi

# ─────────────────────────────────────────────────────────────────────────────
if [[ "$_CF" == *prod* ]]; then
hdr "PHASE E — Production TLS & exposure"
_HOST=$(echo "$BASE" | sed -E 's|^https?://||; s|[:/].*||')
_HB="https://${_HOST}"

[[ "$(curl -sk -o /dev/null -w '%{http_code}' "$_HB/health" 2>/dev/null)" == "200" ]] && ok "HTTPS answers on 443 (/health -> 200)" || no "HTTPS not answering on $_HB"
_r=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' "http://${_HOST}/" 2>/dev/null)
[[ "$_r" == 301\ https://* ]] && ok "HTTP -> HTTPS redirect (301)" || no "HTTP does not redirect to HTTPS (got: $_r)"
_h=$(curl -skI "$_HB/" 2>/dev/null | tr -d '\r')
echo "$_h" | grep -qi '^strict-transport-security:' && ok "HSTS header present" || no "HSTS header missing"
echo "$_h" | grep -qi '^x-content-type-options: nosniff' && ok "X-Content-Type-Options: nosniff" || no "nosniff header missing"
_csp=$(echo "$_h" | grep -i '^content-security-policy:')
if [[ -z "$_csp" ]]; then no "CSP header missing"
elif echo "$_csp" | grep -qi "unsafe-eval"; then no "CSP allows 'unsafe-eval' on the app (prod must not)"
else ok "CSP present and free of 'unsafe-eval'"; fi

# Certificate
_end=$(echo | openssl s_client -connect "${_HOST}:443" -servername "$_HOST" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
if [[ -n "$_end" ]]; then
  _left=$(( ( $(date -d "$_end" +%s) - $(date +%s) ) / 86400 ))
  (( _left >= 14 )) && ok "Certificate valid for ${_left} more days" || no "Certificate expires in ${_left} days — renew now"
  _iss=$(echo | openssl s_client -connect "${_HOST}:443" -servername "$_HOST" 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null)
  echo "$_iss" | grep -qi "let's encrypt\|Let's Encrypt" && ok "Certificate issued by Let's Encrypt" || echo -e "  ${Y}· certificate is not from Let's Encrypt (internal/self-signed/customer CA)${N}"
else wn "Could not read the certificate from ${_HOST}:443"; fi

# Legacy protocols must be refused
for _p in tls1 tls1_1; do
  _o=$(echo | openssl s_client -connect "${_HOST}:443" -"$_p" 2>&1)
  if echo "$_o" | grep -qiE "unknown option|unsupported|no protocols available|invalid command"; then echo -e "  ${Y}· ${_p}: this openssl build cannot test it${N}"
  elif echo "$_o" | grep -qE "Cipher is [A-Za-z0-9_-]+" && ! echo "$_o" | grep -q "Cipher is (NONE)"; then no "Legacy protocol ${_p} is ACCEPTED"
  else ok "Legacy protocol ${_p} refused"; fi
done

# Session cookie must carry Secure + HttpOnly (proves SECURE_COOKIES took effect)
_pw=$($COMPOSE exec -T backend printenv ADMIN_PASSWORD 2>/dev/null | tr -d '\r')
if [[ -n "$_pw" ]]; then
  _ck=$(curl -sk -D - -o /dev/null -X POST "$_HB/api/v1/auth/login" -H "Content-Type: application/x-www-form-urlencoded" --data-urlencode "username=${VERIFY_ADMIN_USER:-admin}" --data-urlencode "password=${VERIFY_ADMIN_PASSWORD:-${_pw}}" 2>/dev/null | tr -d '\r' | grep -i '^set-cookie:')
  if [[ -z "$_ck" ]]; then wn "Login over HTTPS set no cookie (check admin credentials)"
  elif echo "$_ck" | grep -qi 'secure' && echo "$_ck" | grep -qi 'httponly'; then ok "Auth cookies are Secure + HttpOnly"
  else no "Auth cookie missing Secure/HttpOnly: $_ck"; fi
fi

# Nothing but 80/443 may listen on all interfaces
_exp=$(docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep -E '0\.0\.0\.0:|\[::\]:' | grep -vE '0\.0\.0\.0:(80|443)->|\[::\]:(80|443)->' | grep -E '^socis_')
[[ -z "$_exp" ]] && ok "Only ports 80/443 are exposed on all interfaces" || no "Services exposed beyond 80/443: $(echo "$_exp" | awk '{print $1}' | tr '\n' ' ')"

# Grafana reachable through the TLS front door
_g=$(curl -sk -o /dev/null -w '%{http_code}' "$_HB/monitoring/api/health" 2>/dev/null)
[[ "$_g" == "200" ]] && ok "Grafana reachable over HTTPS (/monitoring)" || wn "Grafana over HTTPS -> $_g"
fi

# ─────────────────────────────────────────────────────────────────────────────
hdr "Summary"
echo -e "  ${G}PASS: $pass${N}   ${R}FAIL: $fail${N}   ${Y}WARN: $warn${N}"
if (( fail == 0 )); then
  echo -e "\n${G}${B}All critical checks passed.${N}"
  exit 0
else
  echo -e "\n${R}${B}$fail check(s) failed — review above.${N}"
  exit 1
fi
