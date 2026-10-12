"""
SOCIS-AI-PT — LLM Service
Multi-model LLM router supporting an external Ollama server plus OpenAI, Anthropic, OpenRouter, Grok and Mistral.
Handles streaming responses and agentic tool dispatch.
"""

import re
import json
from typing import Any, AsyncGenerator, Dict, Optional, List
from enum import Enum

import httpx

from app.config import settings


class LLMProvider(str, Enum):
    # Ollama is an EXTERNAL server (Admin -> Settings -> Remote Ollama). The legacy
    # "ollama_local" name is mapped to this by app.core.llm_providers.normalize_provider.
    OLLAMA_REMOTE = "ollama_remote"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OPENROUTER = "openrouter"
    GROK = "grok"
    MISTRAL = "mistral"


# ─── System Prompt ────────────────────────────────────────────
# Generated dynamically from registered MCP servers.
# Importing here gives a static snapshot at startup; llm.py re-calls
# build_system_prompt() at request time so new servers appear instantly.

from app.services.system_prompt import build_system_prompt as _build_system_prompt

SYSTEM_PROMPT: str = _build_system_prompt()



class LLMService:
    """Multi-provider LLM router with streaming support."""

    def __init__(self):
        # Default timeout for non-stream calls.
        self.timeout = httpx.Timeout(settings.OLLAMA_TIMEOUT, connect=10)
        # Streaming responses can legitimately take longer than OLLAMA_TIMEOUT,
        # so disable read timeout while preserving connect/write/pool guards.
        self.stream_timeout = httpx.Timeout(connect=10, read=None, write=60, pool=60)

    # ─── Ollama (external server) ─────────────────────────────

    async def chat_ollama(
        self,
        prompt: str,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        stream: bool = True,
        system_prompt: Optional[str] = None,
    ) -> AsyncGenerator[str, None]:
        """Send prompt to Ollama and stream response tokens.

        Ollama is an EXTERNAL server. Resolve the endpoint from the explicit
        base_url (the admin-configured URL, or a workflow node's remote_url),
        else the OLLAMA_REMOTE_URL environment default.
        """
        _ollama_url = base_url or settings.OLLAMA_REMOTE_URL
        if not _ollama_url:
            yield (
                "[!] No Ollama server configured. Add one in "
                "Admin → Settings → Remote Ollama Configuration (enter the server "
                "URL and click Test, then Save), or select an API provider "
                "(OpenAI, Anthropic, OpenRouter, Grok, Mistral) in LLM settings."
            )
            return
        # SSRF guard: the URL may originate from a workflow node. Private ranges are allowed
        # (the external Ollama is normally on the internal network); loopback, link-local and
        # cloud-metadata addresses never are.
        try:
            from app.core.netguard import acheck_url
            await acheck_url(_ollama_url, allow_private=True)
        except ValueError as exc:
            yield f"[!] The Ollama server URL is not allowed: {exc}"
            return
        url = f"{_ollama_url.rstrip('/')}/api/generate"
        model = model or settings.OLLAMA_REMOTE_MODEL or settings.OLLAMA_DEFAULT_MODEL

        payload = {
            "model": model,
            "prompt": prompt,
            "stream": stream,
            "options": {
                "num_predict": 4096,
                "temperature": 0.7,
                "top_p": 0.9,
                "top_k": 10,
            },
        }
        if system_prompt:
            payload["system"] = system_prompt

        timeout = self.stream_timeout if stream else self.timeout
        async with httpx.AsyncClient(timeout=timeout) as client:
            if stream:
                async with client.stream("POST", url, json=payload) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        if line:
                            try:
                                data = json.loads(line)
                                if data.get("error"):
                                    raise RuntimeError(f"Ollama error: {data['error']}")
                                token = data.get("response", "")
                                if token:
                                    yield token
                                if data.get("done"):
                                    break
                            except json.JSONDecodeError:
                                continue
            else:
                response = await client.post(url, json=payload)
                response.raise_for_status()
                data = response.json()
                yield data.get("response", "")

    # ─── OpenAI ───────────────────────────────────────────────

    async def chat_openai(
        self,
        messages: List[dict[str, Any]],
        model: Optional[str] = None,
        stream: bool = True,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> AsyncGenerator[str, None]:
        """Send messages to OpenAI API and stream response.

        api_key/base_url: an admin-saved LLMConfig override (Admin -> AI providers -> Add LLM Provider), resolved by
        app.core.llm_providers.resolve_llm_credentials. Falls back to the .env variable when not given, exactly as
        before this parameter existed.
        """
        _api_key = api_key or settings.OPENAI_API_KEY
        if not _api_key:
            yield "[!] OpenAI API key not configured."
            return

        url = f"{(base_url or settings.OPENAI_BASE_URL).rstrip('/')}/chat/completions"
        model = model or settings.OPENAI_MODEL

        payload = {
            "model": model,
            "messages": messages,
            "stream": stream,
            "temperature": 0.7,
            "max_tokens": 4096,
        }

        headers = {
            "Authorization": f"Bearer {_api_key}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            if stream:
                async with client.stream("POST", url, json=payload, headers=headers) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        if line.startswith("data: "):
                            data_str = line[6:]
                            if data_str == "[DONE]":
                                break
                            try:
                                data = json.loads(data_str)
                                token = data["choices"][0]["delta"].get("content", "")
                                if token:
                                    yield token
                            except (json.JSONDecodeError, KeyError):
                                continue
            else:
                response = await client.post(url, json=payload, headers=headers)
                response.raise_for_status()
                data = response.json()
                yield data["choices"][0]["message"]["content"]

    # ─── Anthropic ────────────────────────────────────────────

    async def chat_anthropic(
        self,
        messages: List[dict[str, Any]],
        model: Optional[str] = None,
        stream: bool = True,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> AsyncGenerator[str, None]:
        """Send messages to Anthropic API and stream response.

        api_key/base_url: an admin-saved LLMConfig override, resolved by
        app.core.llm_providers.resolve_llm_credentials. Falls back to .env when not given.
        """
        _api_key = api_key or settings.ANTHROPIC_API_KEY
        if not _api_key:
            yield "[!] Anthropic API key not configured."
            return

        url = f"{(base_url or 'https://api.anthropic.com').rstrip('/')}/v1/messages"
        model = model or settings.ANTHROPIC_MODEL

        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": 4096,
            "stream": stream,
        }

        headers = {
            "x-api-key": _api_key,
            "content-type": "application/json",
            "anthropic-version": "2023-06-01",
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            if stream:
                async with client.stream("POST", url, json=payload, headers=headers) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        if line.startswith("data: "):
                            try:
                                data = json.loads(line[6:])
                                if data.get("type") == "content_block_delta":
                                    token = data["delta"].get("text", "")
                                    if token:
                                        yield token
                            except (json.JSONDecodeError, KeyError):
                                continue
            else:
                response = await client.post(url, json=payload, headers=headers)
                response.raise_for_status()
                data = response.json()
                yield data["content"][0]["text"]

    # ─── OpenRouter ───────────────────────────────────────────

    async def chat_openrouter(
        self,
        messages: List[dict[str, Any]],
        model: Optional[str] = None,
        stream: bool = True,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> AsyncGenerator[str, None]:
        """Send messages to OpenRouter API (OpenAI-compatible) and stream response.

        api_key/base_url: an admin-saved LLMConfig override, resolved by
        app.core.llm_providers.resolve_llm_credentials. Falls back to .env when not given.
        """
        _api_key = api_key or settings.OPENROUTER_API_KEY
        if not _api_key:
            yield "[!] OpenRouter API key not configured."
            return

        url = f"{(base_url or settings.OPENROUTER_BASE_URL).rstrip('/')}/chat/completions"
        model = model or settings.OPENROUTER_MODEL

        payload = {
            "model": model,
            "messages": messages,
            "stream": stream,
            "temperature": 0.7,
            "max_tokens": 4096,
        }

        headers = {
            "Authorization": f"Bearer {_api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://socis-ai-pt",
            "X-Title": "SOCIS-AI-PT",
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            if stream:
                async with client.stream("POST", url, json=payload, headers=headers) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        if line.startswith("data: "):
                            data_str = line[6:]
                            if data_str == "[DONE]":
                                break
                            try:
                                data = json.loads(data_str)
                                token = data["choices"][0]["delta"].get("content", "")
                                if token:
                                    yield token
                            except (json.JSONDecodeError, KeyError):
                                continue
            else:
                response = await client.post(url, json=payload, headers=headers)
                response.raise_for_status()
                data = response.json()
                yield data["choices"][0]["message"]["content"]

    # ─── xAI Grok ─────────────────────────────────────────────

    async def chat_grok(
        self,
        messages: List[dict[str, Any]],
        model: Optional[str] = None,
        stream: bool = True,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> AsyncGenerator[str, None]:
        """Send messages to xAI Grok API (OpenAI-compatible) and stream response.

        api_key/base_url: an admin-saved LLMConfig override, resolved by
        app.core.llm_providers.resolve_llm_credentials. Falls back to .env when not given.
        """
        _api_key = api_key or settings.GROK_API_KEY
        if not _api_key:
            yield "[!] Grok (xAI) API key not configured."
            return

        url = f"{(base_url or settings.GROK_BASE_URL).rstrip('/')}/chat/completions"
        model = model or settings.GROK_MODEL

        payload = {
            "model": model,
            "messages": messages,
            "stream": stream,
            "temperature": 0.7,
            "max_tokens": 4096,
        }

        headers = {
            "Authorization": f"Bearer {_api_key}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            if stream:
                async with client.stream("POST", url, json=payload, headers=headers) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        if line.startswith("data: "):
                            data_str = line[6:]
                            if data_str == "[DONE]":
                                break
                            try:
                                data = json.loads(data_str)
                                token = data["choices"][0]["delta"].get("content", "")
                                if token:
                                    yield token
                            except (json.JSONDecodeError, KeyError):
                                continue
            else:
                response = await client.post(url, json=payload, headers=headers)
                response.raise_for_status()
                data = response.json()
                yield data["choices"][0]["message"]["content"]

    # ─── Mistral ──────────────────────────────────────────────

    async def chat_mistral(
        self,
        messages: List[dict[str, Any]],
        model: Optional[str] = None,
        stream: bool = True,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> AsyncGenerator[str, None]:
        """Send messages to Mistral AI API (OpenAI-compatible) and stream response.

        api_key/base_url: an admin-saved LLMConfig override, resolved by
        app.core.llm_providers.resolve_llm_credentials. Falls back to .env when not given.
        """
        _api_key = api_key or settings.MISTRAL_API_KEY
        if not _api_key:
            yield "[!] Mistral API key not configured."
            return

        url = f"{(base_url or settings.MISTRAL_BASE_URL).rstrip('/')}/chat/completions"
        model = model or settings.MISTRAL_MODEL

        payload = {
            "model": model,
            "messages": messages,
            "stream": stream,
            "temperature": 0.7,
            "max_tokens": 4096,
        }

        headers = {
            "Authorization": f"Bearer {_api_key}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            if stream:
                async with client.stream("POST", url, json=payload, headers=headers) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        if line.startswith("data: "):
                            data_str = line[6:]
                            if data_str == "[DONE]":
                                break
                            try:
                                data = json.loads(data_str)
                                token = data["choices"][0]["delta"].get("content", "")
                                if token:
                                    yield token
                            except (json.JSONDecodeError, KeyError):
                                continue
            else:
                response = await client.post(url, json=payload, headers=headers)
                response.raise_for_status()
                data = response.json()
                yield data["choices"][0]["message"]["content"]

    # ─── Router ───────────────────────────────────────────────

    async def chat(
        self,
        prompt: str,
        provider: LLMProvider = LLMProvider.OLLAMA_REMOTE,
        model: Optional[str] = None,
        messages: Optional[List[dict[str, Any]]] = None,
        stream: bool = True,
        base_url: Optional[str] = None,
        remote_url: Optional[str] = None,
        system_prompt: Optional[str] = None,
        api_key: Optional[str] = None,
    ) -> AsyncGenerator[str, None]:
        """Route chat request to the appropriate LLM provider.

        api_key: an admin-saved LLMConfig override for a non-Ollama provider (resolved by the caller via
        app.core.llm_providers.resolve_llm_credentials). Ignored for Ollama, which uses remote_url/base_url instead.
        When not given, each provider method falls back to its .env variable exactly as before this existed.
        """
        # Normalize provider to string so callers can pass either:
        # - app.services.llm_service.LLMProvider
        # - app.models.llm_config.LLMProvider
        # - raw provider strings (e.g. "ollama_local")
        from app.core.llm_providers import normalize_provider
        provider_value = normalize_provider(provider.value if isinstance(provider, Enum) else str(provider))

        # Metrics (observability #9): count the request and time the full stream.
        import time as _time
        from app.core import metrics as _m
        _prov_label = "ollama" if provider_value == "ollama_remote" else provider_value
        _m.LLM_REQUESTS.labels(_prov_label).inc()
        _llm_start = _time.perf_counter()
        _observed = False

        def _observe_once():
            nonlocal _observed
            if not _observed:
                _observed = True
                try:
                    _m.LLM_LATENCY.observe(_time.perf_counter() - _llm_start)
                    _m.LLM_PROVIDER_UP.labels(_prov_label).set(1)
                except Exception:
                    pass

        # Ollama is an external server; legacy "ollama_local" was normalised above.
        try:
            if provider_value == LLMProvider.OLLAMA_REMOTE.value:
                url = remote_url or base_url or settings.OLLAMA_REMOTE_URL or None
                async for token in self.chat_ollama(prompt, model, url, stream, system_prompt):
                    yield token
            elif provider_value == LLMProvider.OPENAI.value:
                msgs = messages or [{"role": "user", "content": prompt}]
                async for token in self.chat_openai(msgs, model, stream, api_key=api_key, base_url=base_url):
                    yield token
            elif provider_value == LLMProvider.ANTHROPIC.value:
                msgs = messages or [{"role": "user", "content": prompt}]
                async for token in self.chat_anthropic(msgs, model, stream, api_key=api_key, base_url=base_url):
                    yield token
            elif provider_value == LLMProvider.OPENROUTER.value:
                msgs = messages or [{"role": "user", "content": prompt}]
                async for token in self.chat_openrouter(msgs, model, stream, api_key=api_key, base_url=base_url):
                    yield token
            elif provider_value == LLMProvider.GROK.value:
                msgs = messages or [{"role": "user", "content": prompt}]
                async for token in self.chat_grok(msgs, model, stream, api_key=api_key, base_url=base_url):
                    yield token
            elif provider_value == LLMProvider.MISTRAL.value:
                msgs = messages or [{"role": "user", "content": prompt}]
                async for token in self.chat_mistral(msgs, model, stream, api_key=api_key, base_url=base_url):
                    yield token
            else:
                raise ValueError(f"Unsupported LLM provider: {provider_value}")
        finally:
            _observe_once()

    # ─── Response Parsing ─────────────────────────────────────

    @staticmethod
    def parse_vulnerabilities(response: str) -> List[Dict]:
        """Parse VULN: lines from AI response into dicts, with markdown fallback."""
        vulns = []
        lines = response.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if line.startswith("VULN:"):
                vuln = {"vuln_name": "", "severity": "medium", "port": "", "service": "", "description": "", "fix": ""}
                parts = line.split("|")
                for part in parts:
                    part = part.strip()
                    if part.startswith("VULN:"):
                        vuln["vuln_name"] = part.replace("VULN:", "").strip()
                    elif part.startswith("SEVERITY:"):
                        vuln["severity"] = part.replace("SEVERITY:", "").strip().lower()
                    elif part.startswith("PORT:"):
                        vuln["port"] = part.replace("PORT:", "").strip()
                    elif part.startswith("SERVICE:"):
                        vuln["service"] = part.replace("SERVICE:", "").strip()
                j = i + 1
                while j < len(lines) and j <= i + 5:
                    next_line = lines[j].strip()
                    if next_line.startswith("VULN:"):
                        break
                    if next_line.startswith("DESC:"):
                        vuln["description"] = next_line.replace("DESC:", "").strip()
                    elif next_line.startswith("FIX:"):
                        vuln["fix"] = next_line.replace("FIX:", "").strip()
                    j += 1
                if vuln["vuln_name"]:
                    vulns.append(vuln)
            i += 1

        # Fallback: parse common markdown vulnerability list format
        if not vulns:
            vulns = LLMService._parse_vulnerabilities_markdown(response)

        return vulns

    @staticmethod
    def _parse_vulnerabilities_markdown(response: str) -> List[Dict]:
        """Fallback parser for markdown-formatted vulnerability lists."""
        vulns = []
        lines = response.splitlines()
        skip_headers = {
            "vulnerabilities", "summary", "immediate actions", "further steps",
            "nmap scan results", "analysis of", "open ports", "web services detected",
            "sqlmap results", "structured vulnerability list",
        }
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            vuln_name = None

            # Match: #### 1. **Name** or ### **Name** or ## **Name**
            header_match = re.match(r'^#{1,6}\s+\d*\.?\s*\*\*(.+?)\*\*', line)
            # Match: - **Name**: or - **Name** (as sub-item vuln name)
            bullet_match = re.match(r'^[-*]\s+\*\*(.+?)\*\*:?\s*$', line) if not header_match else None

            if header_match:
                vuln_name = header_match.group(1).strip()
            elif bullet_match:
                vuln_name = bullet_match.group(1).strip()

            if vuln_name and len(vuln_name) > 3:
                if not any(s in vuln_name.lower() for s in skip_headers):
                    vuln: dict = {
                        "vuln_name": vuln_name,
                        "severity": "medium",
                        "port": "",
                        "service": "",
                        "description": "",
                        "fix": "",
                    }
                    # Scan next lines for description, fix, severity
                    j = i + 1
                    while j < len(lines) and j <= i + 12:
                        nl = lines[j].strip()
                        sev = re.search(r'\b(critical|high|medium|low)\b', nl, re.IGNORECASE)
                        if sev and vuln["severity"] == "medium":
                            vuln["severity"] = sev.group(1).lower()
                        desc_m = re.match(r'^[-*]?\s*(?:description|desc):\s*(.+)', nl, re.IGNORECASE)
                        if desc_m and not vuln["description"]:
                            vuln["description"] = desc_m.group(1).strip()
                        fix_m = re.match(r'^[-*]?\s*(?:recommendation|fix|remediation):\s*(.+)', nl, re.IGNORECASE)
                        if fix_m and not vuln["fix"]:
                            vuln["fix"] = fix_m.group(1).strip()
                        port_m = re.search(r'\bport[: ]+(\d+)', nl, re.IGNORECASE)
                        if port_m and not vuln["port"]:
                            vuln["port"] = port_m.group(1)
                        j += 1
                    # Use first non-empty non-header line as description if none found
                    if not vuln["description"]:
                        for j in range(i + 1, min(i + 6, len(lines))):
                            candidate = lines[j].strip().lstrip("-*").strip()
                            if candidate and not candidate.startswith("#") and len(candidate) > 10:
                                vuln["description"] = candidate
                                break
                    vulns.append(vuln)
            i += 1
        return vulns

    @staticmethod
    def parse_exploits(response: str) -> List[Dict]:
        """Parse EXPLOIT: lines from AI response."""
        exploits = []
        lines = response.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if line.startswith("EXPLOIT:"):
                exploit = {"exploit_name": "", "tool_used": "", "payload": "", "result": "unknown", "notes": ""}
                parts = line.split("|")
                for part in parts:
                    part = part.strip()
                    if part.startswith("EXPLOIT:"):
                        exploit["exploit_name"] = part.replace("EXPLOIT:", "").strip()
                    elif part.startswith("TOOL:"):
                        exploit["tool_used"] = part.replace("TOOL:", "").strip()
                    elif part.startswith("PAYLOAD:"):
                        exploit["payload"] = part.replace("PAYLOAD:", "").strip()
                j = i + 1
                while j < len(lines) and j <= i + 4:
                    next_line = lines[j].strip()
                    if next_line.startswith("RESULT:"):
                        exploit["result"] = next_line.replace("RESULT:", "").strip()
                    elif next_line.startswith("NOTES:"):
                        exploit["notes"] = next_line.replace("NOTES:", "").strip()
                    j += 1
                if exploit["exploit_name"]:
                    exploits.append(exploit)
            i += 1
        return exploits

    @staticmethod
    def parse_risk_level(response: str) -> str:
        match = re.search(r'RISK_LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW)', response, re.IGNORECASE)
        if match:
            return match.group(1).upper()
        # Fallback: infer from severity keywords in the response (prioritized top-to-bottom)
        text = response.lower()
        
        # CRITICAL patterns: RCE, arbitrary code execution, unauthenticated access, exploitable vulnerabilities
        if re.search(r'\b(critical|criticality|critically|critical.{0,3}severity|critical.{0,3}risk|'
                     r'rce|remote code execution|arbitrary code execution|code execution|'
                     r'unauthenticated|unauthenticated.{0,3}access|zero.?day|zeroday|'
                     r'remote access|unauthorized access|complete compromise|'
                     r'authentication bypass|session hijacking|'
                     r'cvss.{0,3}(9|10)|cvss.score.{0,3}(9|10))\b', text):
            return "CRITICAL"
        
        # HIGH patterns: SQL injection, command execution, privilege escalation, auth bypass
        if re.search(r'\b(high|high.{0,3}severity|high.{0,3}risk|'
                     r'sql.{0,3}injection|sql.{0,3}inj|sqli|'
                     r'command.{0,3}injection|command.{0,3}exec|os.{0,3}command|'
                     r'privilege.{0,3}escalation|priv.{0,3}esc|privesc|'
                     r'authentication.{0,3}bypass|auth.{0,3}bypass|'
                     r'sensitive.{0,3}data|data.{0,3}exposure|'
                     r'broken.{0,3}auth|broken.{0,3}access|'
                     r'access.{0,3}control.{0,3}bypass|path.{0,3}traversal|'
                     r'xxe|xml.{0,3}external|deserialization|'
                     r'ldap.{0,3}injection|xpath.{0,3}injection|'
                     r'code.{0,3}injection|remote.{0,3}include)\b', text):
            return "HIGH"
        
        # MEDIUM patterns: XSS, CSRF, open redirect, SSRF, IDOR, weak encryption
        if re.search(r'\b(medium|medium.{0,3}severity|medium.{0,3}risk|'
                     r'xss|cross.{0,3}site.{0,3}script|cross.site|'
                     r'csrf|cross.{0,3}site.{0,3}request|xsrf|'
                     r'open.{0,3}redirect|url.{0,3}redirect|redirect|'
                     r'ssrf|server.{0,3}side.{0,3}request|'
                     r'idor|insecure.{0,3}direct|object.{0,3}reference|'
                     r'weak.{0,3}encryption|weak.{0,3}crypto|weak.{0,3}password|'
                     r'missing.{0,3}security.{0,3}header|security.{0,3}header|'
                     r'clickjacking|x.frame|host.{0,3}header|http.{0,3}header|'
                     r'race.{0,3}condition|timing.{0,3}attack|'
                     r'information.{0,3}leak|data.{0,3}leak)\b', text):
            return "MEDIUM"
        
        # LOW patterns: Info disclosure, misconfiguration, deprecated versions, best practices
        if re.search(r'\b(low|low.{0,3}severity|low.{0,3}risk|'
                     r'information.{0,3}disclosure|info.{0,3}disclosure|'
                     r'misconfiguration|misconfigured|badly.{0,3}config|'
                     r'best.{0,3}practice|deprecated|outdated|'
                     r'version.{0,3}disclosure|banner.{0,3}grab|banner|'
                     r'weak.{0,3}ssl|weak.{0,3}tls|ssl.{0,3}config|tls.{0,3}config|'
                     r'debug.{0,3}info|debug.{0,3}mode|debug.{0,3}enabled|'
                     r'unnecessary.{0,3}service|unnecessary.{0,3}port|'
                     r'default.{0,3}credential|default.{0,3}account)\b', text):
            return "LOW"
        
        return "UNKNOWN"


# Singleton
llm_service = LLMService()

__all__ = ["LLMService", "llm_service", "LLMProvider", "SYSTEM_PROMPT"]
