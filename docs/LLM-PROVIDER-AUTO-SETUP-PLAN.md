# LLM Provider Auto-Setup Plan — Administration Settings

> Analysis only. No code changed. Covers: `Admin > AI providers > Add LLM Provider`, with focus on OpenRouter.

## 1. Current behavior (as-built)

### 1.1 Form — `frontend/src/app/(app)/admin/page.tsx`

* State: `llmForm:156` = `{name, provider, model_name, api_url, api_key, is_default}`.
* Modal: `1295-1484`. Labels: `Name *` required, `API URL (optional)`, `API Key (optional)` (`1342-1346`).
* Provider dropdown `1391-1411` from `LLM_PROVIDER_LABELS:51-58`: `ollama_remote, openai, anthropic, openrouter, grok, mistral` (DB + `SUPPORTED_PROVIDERS` in `backend/app/core/llm_providers.py:15` also allow `custom`, hidden in UI).
* Backend validation: `backend/app/api/v1/admin.py:403-410` (`LLMConfigCreate`): only `name/provider/model_name: str` required; `api_url/api_key: Optional`. No provider allow-list check — invalid value fails at Postgres `llm_provider` enum (`backend/alembic/versions/018_llm_provider_expansion.py`).
* Submit guard `1334`: `ollama_remote` must have `model_name`, otherwise `400`.

### 1.2 Model field is provider-dependent

* `ollama_remote` only: dropdown populated by `loadModelsForProvider:309-337` → `GET /llm/models?provider=ollama_remote&configured_only=false&remote_url=...` (`frontend/src/lib/api.ts:222`). Backend hits `{url}/api/tags` (`backend/app/api/v1/llm.py:1225`), filters embeddings. Empty → manual input + warning `1445-1461`.
* All others (`1368-1389`): plain `<input required>` with placeholder hints only:
  `openai: gpt-4o`, `anthropic: claude-sonnet-4-5`, `openrouter: openai/gpt-4o`, `grok: grok-4`, `mistral: mistral-large-latest`.
* `loadModelsForProvider:309-313` early-returns `[]` for non-Ollama — no discovery.

### 1.3 OpenRouter answers

| Question | Answer |
|---|---|
| Need URL? | No. Leave blank. Stored to `llm_configs.api_url` (`admin.py:444-448`) but never read for inference. Effective URL is `settings.OPENROUTER_BASE_URL` (`backend/app/config.py:121` = `https://openrouter.ai/api/v1`). |
| Need API key in modal? | Stored (Fernet → `api_key_encrypted`), but **not used**. Effective key is `settings.OPENROUTER_API_KEY` from `.env`. See §2. |
| Must type model? | Yes. Required in UI + DB `model_name nullable=False` (`backend/app/models/llm_config.py:38`). Passed verbatim as `model` in `chat/completions` payload (`backend/app/services/llm_service.py:240-242`). Must be namespaced: `openai/gpt-4o`, `anthropic/claude-...`, etc. Wrong string = OpenRouter `404`. Also gates allow-list: `llm.py:881-886` rejects `400 Model 'X' is not allowed ... Configure it in Admin → LLM Configs first` if not in `LLMConfig` rows (`_allowed_models_by_provider:800-809`). |

## 2. Where are other-provider keys stored?

1. **Per-row (stored, unused):** `llm_configs.api_key_encrypted: Text` (`models/llm_config.py:40`). Written `admin.py:453` via `encrypt_secret` (`core/encryption.py`). Key = `ENCRYPTION_KEY` (`.env:73`, `deploy/docker/env.dev:24`, `env.prod:31`; ephemeral + lost on restart if unset). `GET /admin/llm-configs:413-432` omits key/URL. `grep decrypt_secret` → zero callers for `llm_configs` (only TOTP, SSO/SMTP, plugins, webhooks use it).
2. **Env (effective):** `backend/app/config.py:110-131`: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY`, `GROK_API_KEY`, `MISTRAL_API_KEY` (+ `*_BASE_URL/MODEL`). Consumed in `llm_service.py:133,184,233,286,338` (e.g. `Bearer {settings.OPENROUTER_API_KEY}` → `{BASE_URL}/chat/completions`). Placeholders in `deploy/docker/.env.example:48-49`, `env.dev:103-104`.
3. **Nowhere else:** `sanitize_user_llm_settings` (`core/llm_providers.py:59-70`) strips `*_api_key` + `ollama_base_url` from user settings. No per-user keys.

Consequence: `GET /llm/status:1338-1343` checks only `settings.*`, so a DB-added OpenRouter key still shows `configured:false`.

## 3. Target UX

`Select provider → paste API key (+ optional URL for custom/proxy) → Test / Fetch Models → see count + pills (reuse `testResult:164,1189-1226`) → pick model from dropdown → Save.` Same as Remote Ollama card today (`testRemoteOllamaConnection:426-447`).

## 4. Phases

### Phase 1 — Fetch-models endpoint + dropdown (read-only)

* New `POST /api/v1/admin/llm-configs/fetch-models` in `backend/app/api/v1/admin.py`, `require_permission("llm:configure")`, 10s timeout, `netguard.acheck_url`, never log key. Body `{provider, api_key, api_url?}` → `{reachable, models[], error?}`.
* Upstream mapping:
  * `openai`: `GET {api_url||https://api.openai.com/v1}/models` + `Bearer` → `data[].id`
  * `openrouter`: `GET {api_url||https://openrouter.ai/api/v1}/models` (+ `Bearer` to validate) → `data[].id`
  * `anthropic`: `GET https://api.anthropic.com/v1/models` + `x-api-key` + `anthropic-version: 2023-06-01` → `data[].id`
  * `grok`: `GET {api_url||https://api.x.ai/v1}/models` + `Bearer` → `data[].id`
  * `mistral`: `GET {api_url||https://api.mistral.ai/v1}/models` + `Bearer` → `data[].id`
  * `ollama_remote`: keep `GET {url}/api/tags` (`llm.py:1225`).
* Frontend `admin/page.tsx`: generalize `loadModelsForProvider` beyond Ollama, add Fetch button, render `<select>` when `availableModels>0` (reuse `1424-1442`), block save until selection matches.
* Accept: key in → live model count + selectable list; fail → manual input + visible error.

### Phase 2 — Use stored key/url at runtime

* Extend `chat_openai/anthropic/openrouter/grok/mistral(api_key?, base_url?)` in `backend/app/services/llm_service.py:126-377` (only `chat_ollama` takes URL today).
* Resolvers in `llm.py:chat:870-920`, `scans.py:353`, `tools.py:_llm_ai_generate:367`: load matching `LLMConfig`, `decrypt_secret(api_key_encrypted)`, prefer `c.api_key/c.api_url`, fallback `settings.*`.
* Accept: AI Chat + Scan manual analysis + Payload Generator work with DB key, `.env` fallback intact.

### Phase 3 — Fix Ollama-hardcoded consumers

* `tasks/scan_worker.py:3217-3253` workflow LLM node fallback forces `OLLAMA_REMOTE` → fallback to same `provider`.
* `api/v1/findings.py:411-426` non-Ollama default uses `OLLAMA_DEFAULT_MODEL` → default to `active_cfgs[0].model_name` (pattern from `scans.py`).
* Accept: workflow + finding analysis stay on selected provider.

### Phase 4 — Status/models unification

* `llm.py:1304-1359 /status`, `1186-1299 /models`, `tools.py:490-543 llm-options`: merge `settings.*` + `LLMConfig` rows, never return secrets.
* Accept: Admin-added provider shows `connected:true` + models in pickers (`LLMProviderSelector.tsx`, `ChatModelPicker`).

### Phase 5 — Hardening / QA

* SSRF: private ranges only for Ollama; public HTTPS for cloud; block metadata/loopback. Rate-limit fetch endpoint. Audit `admin:llm_config_create/delete` already in `admin.py:456,478`.
* E2E per provider: list → save → chat → scan analysis → workflow run → key rotation (blank = keep, like SSO/plugins pattern).

## 5. Post-phase usage matrix

| Consumer | After Phase 2, extra code? |
|---|---|
| AI Chat (`llm.py:976,1081`) | No — already generic `llm_service.chat(provider, model)`. |
| Scans manual analysis (`scans.py:353`) | No — generic allow-list. |
| Payload/Wordlist (`tools.py:337,346`) | No — generic `ai_provider` passthrough. |
| Workflows LLM node (`scan_worker.py:3250`) | Yes — Phase 3 fallback fix. |
| Findings analyze (`findings.py:414`) | Yes — Phase 3 default-model fix. |
| Status/pickers | Yes — Phase 4 merge. |
