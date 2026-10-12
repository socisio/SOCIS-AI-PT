"""SOCIS-AI-PT — Tools Routes"""
import io
import logging
import os
import re
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse

from app.core.database import get_db
from app.core.security import require_permission
from app.services.tool_service import TOOL_REGISTRY
from app.core import tool_manifest as _manifest

logger = logging.getLogger(__name__)

router = APIRouter()

# ─── Project Upload Constants ──────────────────────────────────────────────────
_PROJECTS_DIR = Path(os.environ.get("PROJECTS_DIR", "/projects"))
_MAX_UPLOAD_BYTES = 50 * 1024 * 1024          # 50 MB hard limit
_MAX_EXTRACTED_FILES = 2_000                   # anti-zip-bomb file count
_MAX_EXTRACTED_BYTES = 200 * 1024 * 1024       # 200 MB anti-zip-bomb size limit
_ALLOWED_EXTENSIONS = {".json", ".js", ".ts", ".mjs", ".cjs", ".md", ".txt",
                       ".yaml", ".yml", ".lock", ".toml", ".npmrc", ".nvmrc",
                       ".gitignore", ".env.example"}
# Only these top-level manifest files are truly required by cve-lite
_MANIFEST_FILES = {"package.json", "package-lock.json", "yarn.lock",
                   "npm-shrinkwrap.json", "pnpm-lock.yaml"}
_SAFE_NAME_RE = re.compile(r"^[a-zA-Z0-9_\-\.]{1,64}$")


def _safe_project_name(raw: str) -> str:
    """Sanitize an uploaded project name; raise HTTPException if invalid."""
    name = raw.strip().rstrip("/")
    if not _SAFE_NAME_RE.match(name):
        raise HTTPException(status_code=400,
                            detail="Invalid project name. Use only letters, digits, hyphens, underscores, dots (max 64 chars).")
    if name in {".", ".."}:
        raise HTTPException(status_code=400, detail="Invalid project name.")
    return name


def _safe_member_path(member_path: str, dest: Path) -> Path | None:
    """
    Resolve an archive member path relative to dest.
    Returns None if the resolved path escapes dest (path traversal guard).
    """
    # Strip leading / and drive letters
    clean = re.sub(r"^([a-zA-Z]:)?[/\\]+", "", member_path)
    resolved = (dest / clean).resolve()
    try:
        resolved.relative_to(dest.resolve())
        return resolved
    except ValueError:
        return None  # traversal attempt — skip silently


def _strip_prefix(member_path: str) -> str:
    """
    Strip a common top-level directory from archive member paths.
    e.g. 'my-app/package.json' → 'package.json'
    Only strips if ALL files share the same top-level component.
    This function is applied per-member; caller must first compute whether
    stripping is appropriate via _should_strip_prefix().
    """
    parts = member_path.replace("\\", "/").lstrip("/").split("/", 1)
    return parts[1] if len(parts) > 1 else parts[0]


def _zip_common_prefix(zf: zipfile.ZipFile) -> bool:
    """Return True if all non-dir members share a single top-level directory."""
    tops: set[str] = set()
    for info in zf.infolist():
        if info.is_dir():
            continue
        parts = info.filename.replace("\\", "/").lstrip("/").split("/")
        if len(parts) < 2:
            return False  # file at root level — no common prefix
        tops.add(parts[0])
    return len(tops) == 1


def _tar_common_prefix(tf: tarfile.TarFile) -> bool:
    """Return True if all file members share a single top-level directory."""
    tops: set[str] = set()
    for member in tf.getmembers():
        if not member.isfile():
            continue
        parts = member.name.replace("\\", "/").lstrip("/").split("/")
        if len(parts) < 2:
            return False
        tops.add(parts[0])
    return len(tops) == 1


def _extract_zip(data: bytes, dest: Path) -> tuple[int, int]:
    """Extract a zip archive to dest with safety checks. Returns (file_count, byte_count)."""
    file_count = 0
    byte_count = 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        strip = _zip_common_prefix(zf)
        for info in zf.infolist():
            if info.is_dir():
                continue
            member_path = _strip_prefix(info.filename) if strip else info.filename
            target = _safe_member_path(member_path, dest)
            if target is None:
                continue  # skip traversal attempts
            if target.suffix.lower() not in _ALLOWED_EXTENSIONS and target.name not in _MANIFEST_FILES:
                continue  # skip disallowed file types
            file_count += 1
            byte_count += info.file_size
            if file_count > _MAX_EXTRACTED_FILES:
                raise HTTPException(status_code=400, detail="Archive contains too many files.")
            if byte_count > _MAX_EXTRACTED_BYTES:
                raise HTTPException(status_code=400, detail="Archive exceeds maximum extracted size (200 MB).")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst, length=65536)
    return file_count, byte_count


def _extract_tar(data: bytes, dest: Path) -> tuple[int, int]:
    """Extract a tar/tar.gz archive to dest with safety checks. Returns (file_count, byte_count)."""
    file_count = 0
    byte_count = 0
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        strip = _tar_common_prefix(tf)
        for member in tf.getmembers():
            if not member.isfile():
                continue
            member_path = _strip_prefix(member.name) if strip else member.name
            target = _safe_member_path(member_path, dest)
            if target is None:
                continue
            if target.suffix.lower() not in _ALLOWED_EXTENSIONS and target.name not in _MANIFEST_FILES:
                continue
            file_count += 1
            byte_count += member.size
            if file_count > _MAX_EXTRACTED_FILES:
                raise HTTPException(status_code=400, detail="Archive contains too many files.")
            if byte_count > _MAX_EXTRACTED_BYTES:
                raise HTTPException(status_code=400, detail="Archive exceeds maximum extracted size (200 MB).")
            target.parent.mkdir(parents=True, exist_ok=True)
            fobj = tf.extractfile(member)
            if fobj:
                with open(target, "wb") as dst:
                    shutil.copyfileobj(fobj, dst, length=65536)
    return file_count, byte_count


@router.post("/cve-lite/upload")
async def upload_project(
    file: UploadFile = File(...),
    token: dict = Depends(require_permission("tools:execute")),
):
    """
    Upload a zipped or tar.gz JS/TS project for CVE Lite scanning.

    - Accepts .zip, .tar.gz, .tgz
    - Max upload size: 50 MB; max extracted: 200 MB; max 2000 files
    - Extracts to /projects/<project_name>/ (shared volume with mcp_all)
    - Only extracts known safe file extensions (no executables, no symlinks)
    - Returns the project name to use in the CVE Lite scan config
    """
    # ── Validate filename / content-type ──────────────────────────────────────
    original_name = file.filename or "upload"
    stem = Path(original_name).stem
    # Handle double extensions: project.tar.gz → stem = "project.tar" → strip again
    if stem.endswith(".tar"):
        stem = stem[:-4]
    project_name = _safe_project_name(stem)

    lower_name = original_name.lower()
    if not (lower_name.endswith(".zip") or lower_name.endswith(".tar.gz") or lower_name.endswith(".tgz")):
        raise HTTPException(status_code=400,
                            detail="Only .zip, .tar.gz, and .tgz archives are accepted.")

    # ── Read & size-check ─────────────────────────────────────────────────────
    data = await file.read()
    if len(data) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413,
                            detail=f"Upload exceeds {_MAX_UPLOAD_BYTES // 1024 // 1024} MB limit.")

    # ── Validate archive integrity before extraction ───────────────────────────
    if lower_name.endswith(".zip"):
        if not zipfile.is_zipfile(io.BytesIO(data)):
            raise HTTPException(status_code=400, detail="File is not a valid ZIP archive.")
    else:
        if not tarfile.is_tarfile(io.BytesIO(data)):
            raise HTTPException(status_code=400, detail="File is not a valid tar archive.")

    # ── Extract into a temp dir first, then move atomically ───────────────────
    _PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
    dest = _PROJECTS_DIR / project_name

    with tempfile.TemporaryDirectory(dir=_PROJECTS_DIR, prefix=".tmp_") as tmp_dir:
        tmp_dest = Path(tmp_dir) / project_name
        tmp_dest.mkdir()

        try:
            if lower_name.endswith(".zip"):
                file_count, byte_count = _extract_zip(data, tmp_dest)
            else:
                file_count, byte_count = _extract_tar(data, tmp_dest)
        except HTTPException:
            raise
        except Exception as exc:
            logger.warning("Failed to extract archive", exc_info=True)
            raise HTTPException(status_code=400, detail="Failed to extract archive") from exc

        if file_count == 0:
            raise HTTPException(status_code=400,
                                detail="Archive contains no extractable files (check allowed extensions).")

        # Require at least one package.json or lockfile
        has_manifest = any((tmp_dest / f).exists() for f in _MANIFEST_FILES) or \
                       any(p.name in _MANIFEST_FILES for p in tmp_dest.rglob("*"))
        if not has_manifest:
            raise HTTPException(status_code=400,
                                detail="Archive must contain a package.json, package-lock.json, yarn.lock, or pnpm-lock.yaml.")

        # Move into place (overwrite any previous upload with the same name)
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(tmp_dest, dest)

    return JSONResponse({
        "project_name": project_name,
        "path": f"/projects/{project_name}",
        "files_extracted": file_count,
        "bytes_extracted": byte_count,
        "message": f"Project '{project_name}' ready for CVE Lite scanning.",
    })


@router.delete("/cve-lite/upload/{project_name}")
async def delete_project(
    project_name: str,
    token: dict = Depends(require_permission("tools:execute")),
):
    """Delete an uploaded project from /projects/."""
    safe_name = _safe_project_name(project_name)
    dest = _PROJECTS_DIR / safe_name
    if not dest.exists():
        raise HTTPException(status_code=404, detail=f"Project '{safe_name}' not found.")
    shutil.rmtree(dest)
    return {"message": f"Project '{safe_name}' deleted."}


@router.get("/cve-lite/projects")
async def list_projects(token: dict = Depends(require_permission("tools:read"))):
    """List all uploaded projects available for CVE Lite scanning."""
    _PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
    projects = [
        {"name": d.name, "path": f"/projects/{d.name}"}
        for d in sorted(_PROJECTS_DIR.iterdir())
        if d.is_dir() and not d.name.startswith(".")
    ]
    return {"projects": projects}


@router.get("/manifest")
async def tool_manifest(token: dict = Depends(require_permission("tools:read"))):
    """The full MCP tool manifest the workflow builder renders its tool picker and per-tool forms from. One entry per
    real MCP tool: {server, action, label, category, needs, risk, offensive, hint, fields:[{name,type,required,default,
    enum,hint}]}. Generated from the real tool-server schemas and verified against them by tests/test_tool_manifest.py,
    so the builder can never offer a tool that does not exist or a field the tool does not accept. `offensive` tools are
    shown but gated behind the server's SOCIS_AGENT_ALLOW_OFFENSIVE opt-in before they will run."""
    return {
        "version": _manifest.manifest_version(),
        "tools": _manifest.all_tools(),
        "native_actions": _manifest.native_actions(),
    }


@router.get("/")
async def list_tools(token: dict = Depends(require_permission("tools:read"))):
    """List all available security tools dynamically from the registry."""
    tools = []
    for name, data in TOOL_REGISTRY.items():
        tools.append({
            "name": name,
            "category": data.get("category", "vuln_scan").value if hasattr(data.get("category"), 'value') else data.get("category"),
            "description": data.get("description", ""),
            "installed": True # Could be enhanced to check actual binary existence
        })
    return {"tools": tools, "total": len(tools)}


# ─── Payload Generator proxy endpoints ───────────────────────────────────────

import httpx as _httpx
import logging as _logging
from pydantic import BaseModel as _BaseModel
from typing import Optional as _Optional, List as _List

_PAYLOAD_GEN_URL = os.environ.get("PAYLOAD_GENERATOR_MCP_URL", "http://mcp_all:8124/mcp")
_MCP_AUTH_TOKEN = os.environ.get("MCP_AUTH_TOKEN", "")
_pg_log = _logging.getLogger(__name__)


async def _call_payload_mcp(tool_name: str, arguments: dict) -> dict:
    headers = {}
    if _MCP_AUTH_TOKEN:
        headers["Authorization"] = f"Bearer {_MCP_AUTH_TOKEN}"
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    async with _httpx.AsyncClient(timeout=90.0) as client:
        resp = await client.post(_PAYLOAD_GEN_URL, json=payload, headers=headers)
        resp.raise_for_status()
    data = resp.json()
    if "error" in data:
        raise HTTPException(status_code=502, detail=data["error"].get("message", "MCP error"))
    import json as _json
    content = data.get("result", {}).get("content", [{}])
    text = content[0].get("text", "{}") if content else "{}"
    return _json.loads(text)


class _GeneratePayloadsRequest(_BaseModel):
    vuln_type: str
    target_context: _Optional[str] = None
    cve_id: _Optional[str] = None
    count: int = 10
    use_ai: bool = True
    ai_provider: str = "ollama_remote"  # ollama_remote | openai | anthropic | openrouter | grok | mistral
    ai_model: _Optional[str] = None     # override model name
    ai_base_url: _Optional[str] = None  # DEPRECATED + IGNORED: the Ollama endpoint is admin-only


class _WordlistRequest(_BaseModel):
    vuln_types: _List[str]
    include_ai: bool = False
    deduplicate: bool = True
    ai_provider: str = "ollama_remote"
    ai_model: _Optional[str] = None
    ai_base_url: _Optional[str] = None  # DEPRECATED + IGNORED (see _llm_ai_generate)


async def _llm_ai_generate(
    prompt: str,
    provider: str,
    model: _Optional[str],
    base_url: _Optional[str],
) -> _List[str]:
    """Call llm_service non-streaming and parse payload lines from the response.

    `base_url` is accepted only for backward compatibility and is IGNORED: a caller-supplied URL
    would make the backend call any address the caller chooses (SSRF). The external Ollama server
    is the admin-configured one (Admin -> Settings -> Remote Ollama).
    """
    from app.services.llm_service import llm_service
    from app.core.llm_providers import normalize_provider
    provider = normalize_provider(provider)
    admin_url = None
    api_key = None
    try:
        from app.core.database import async_session
        async with async_session() as _db:
            if provider == "ollama_remote":
                from app.services.settings_service import settings_service
                admin_url = await settings_service.get_ollama_remote_url(_db)
            else:
                # Resolve the admin-saved API key/URL (Admin -> AI providers -> Add LLM Provider) for this provider —
                # previously this always used only the .env variable, same gap as the other call sites.
                from app.core.llm_providers import resolve_llm_credentials
                api_key, admin_url = await resolve_llm_credentials(_db, provider)
    except Exception:
        admin_url = None
        api_key = None
    tokens: _List[str] = []
    try:
        async for token in llm_service.chat(
            prompt=prompt,
            provider=provider,
            model=model or None,
            stream=False,
            base_url=admin_url,
            remote_url=admin_url,
            api_key=api_key,
        ):
            tokens.append(token)
    except Exception as exc:
        _pg_log.warning("AI payload generation failed (%s): %s", provider, exc)
        return []
    text = "".join(tokens)
    return [
        line.strip()
        for line in text.strip().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


@router.post("/payload-generator/generate")
async def generate_payloads(
    body: _GeneratePayloadsRequest,
    token: dict = Depends(require_permission("tools:read")),
):
    """Generate security test payloads for a given vulnerability type."""
    # Always get static payloads from MCP (use_ai=False so MCP skips its own Ollama call)
    args: dict = {"vuln_type": body.vuln_type, "count": body.count, "use_ai": False}
    if body.target_context:
        args["target_context"] = body.target_context
    if body.cve_id:
        args["cve_id"] = body.cve_id
    try:
        result = await _call_payload_mcp("generate_payloads", args)
    except _httpx.HTTPError as e:
        logger.warning("Payload generator MCP unreachable", exc_info=True)
        raise HTTPException(status_code=502, detail="Payload generator MCP unreachable")

    if body.use_ai:
        vuln_desc = result.get("description", body.vuln_type)
        cve_part = f" Specifically target {body.cve_id}." if body.cve_id else ""
        ctx_part = f" Target context: {body.target_context}." if body.target_context else ""
        prompt = (
            f"You are a penetration testing expert. Generate {body.count} unique, creative, and "
            f"effective {vuln_desc} payloads for security testing.{cve_part}{ctx_part} "
            f"Output ONLY the payloads, one per line, no explanations, no numbering, no markdown."
        )
        ai_payloads = await _llm_ai_generate(prompt, body.ai_provider, body.ai_model, body.ai_base_url)
        static = result.get("payloads", [])
        merged = ai_payloads + [p for p in static if p not in ai_payloads]
        result["payloads"] = merged[: body.count]
        result["count"] = len(result["payloads"])
        result["source"] = "ai+static" if ai_payloads else "static_only"
        result["ai_available"] = True
        result["ai_provider"] = body.ai_provider

    return result


@router.post("/payload-generator/wordlist")
async def generate_wordlist(
    body: _WordlistRequest,
    token: dict = Depends(require_permission("tools:read")),
):
    """Build a wordlist from multiple vulnerability types."""
    mcp_body = body.model_dump()
    # Let AI augmentation be handled here when a specific provider is set
    mcp_body["include_ai"] = False
    try:
        result = await _call_payload_mcp("generate_wordlist", mcp_body)
    except _httpx.HTTPError as e:
        logger.warning("Payload generator MCP unreachable", exc_info=True)
        raise HTTPException(status_code=502, detail="Payload generator MCP unreachable")

    if body.include_ai:
        all_ai: _List[str] = []
        for vtype in body.vuln_types:
            prompt = (
                f"You are a penetration testing expert. Generate 10 unique {vtype} security test payloads. "
                f"Output ONLY the payloads, one per line, no explanations, no numbering, no markdown."
            )
            all_ai.extend(await _llm_ai_generate(prompt, body.ai_provider, body.ai_model, body.ai_base_url))

        existing = set(result.get("wordlist", "").splitlines())
        new_payloads = [p for p in all_ai if p not in existing]
        combined = result.get("wordlist", "") + ("\n" + "\n".join(new_payloads) if new_payloads else "")
        result["wordlist"] = combined
        result["total"] = len([l for l in combined.splitlines() if l.strip()])
        result["ai_augmented"] = bool(all_ai)

    return result


@router.get("/payload-generator/types")
async def list_payload_types(
    token: dict = Depends(require_permission("tools:read")),
):
    """List all supported vulnerability payload types."""
    try:
        return await _call_payload_mcp("list_vuln_types", {})
    except _httpx.HTTPError as e:
        logger.warning("Payload generator MCP unreachable", exc_info=True)
        raise HTTPException(status_code=502, detail="Payload generator MCP unreachable")


@router.get("/payload-generator/llm-options")
async def payload_llm_options(
    token: dict = Depends(require_permission("tools:read")),
    db=Depends(get_db),
):
    """Return LLM providers + admin-configured models for AI-enhanced payload generation."""
    from app.config import settings as _settings
    from app.services.settings_service import settings_service as _ss
    from app.models.llm_config import LLMConfig
    from sqlalchemy import select as _select

    # Load all active admin-configured LLM entries
    db_configs = (
        await db.execute(_select(LLMConfig).where(LLMConfig.is_active == True))
    ).scalars().all()

    # Group configured model names by provider
    cfg_by_provider: dict[str, list[str]] = {}
    cfg_default: dict[str, str] = {}
    for c in db_configs:
        from app.core.llm_providers import normalize_provider as _np
        pid = _np(getattr(c.provider, "value", c.provider))
        cfg_by_provider.setdefault(pid, []).append(c.model_name)
        if c.is_default and pid not in cfg_default:
            cfg_default[pid] = c.model_name

    providers: list[dict] = []

    # Ollama is an external server only (the "Remote Ollama" provider below).

    # ── Remote Ollama ─────────────────────────────────────────
    # Only expose models explicitly configured in Admin → LLM Configuration Profiles.
    remote_configured = cfg_by_provider.get("ollama_remote", [])
    remote_url = await _ss.get_ollama_remote_url(db) or getattr(_settings, "OLLAMA_REMOTE_URL", "")
    remote_connected = False
    if remote_url and remote_configured:
        try:
            async with _httpx.AsyncClient(timeout=5) as client:
                r = await client.get(f"{remote_url.rstrip('/')}/api/tags")
            remote_connected = r.status_code == 200
        except Exception:
            pass
        default_remote = (
            cfg_default.get("ollama_remote")
            or (await _ss.get_ollama_remote_model(db))
            or remote_configured[0]
        )
        providers.append({
            "id": "ollama_remote",
            "label": "Ollama (external)",
            "icon": "remote",
            "connected": remote_connected,
            "models": sorted(remote_configured),
            "default_model": default_remote,
            "url": remote_url,
        })

    # ── Cloud providers ────────────────────────────────────────
    # A provider is usable if EITHER its .env variable is set OR an admin has saved an active LLMConfig row for it
    # (Admin -> AI providers -> Add LLM Provider) WITH an API key of its own. Previously this required BOTH a saved
    # config AND the .env variable — so a provider configured purely through the admin UI (the entire point of that
    # feature; no .env edit required) never appeared in the AI chat / payload generator provider list at all.
    cloud_meta = [
        ("openai",     "OpenAI",     getattr(_settings, "OPENAI_API_KEY", "")),
        ("anthropic",  "Anthropic",  getattr(_settings, "ANTHROPIC_API_KEY", "")),
        ("openrouter", "OpenRouter", getattr(_settings, "OPENROUTER_API_KEY", "")),
        ("grok",       "xAI Grok",   getattr(_settings, "GROK_API_KEY", "")),
        ("mistral",    "Mistral",    getattr(_settings, "MISTRAL_API_KEY", "")),
    ]
    cfg_has_own_key: dict[str, bool] = {}
    for c in db_configs:
        from app.core.llm_providers import normalize_provider as _np2
        pid2 = _np2(getattr(c.provider, "value", c.provider))
        if c.api_key_encrypted:
            cfg_has_own_key[pid2] = True
    for pid, plabel, env_key in cloud_meta:
        cloud_configured = cfg_by_provider.get(pid, [])
        if cloud_configured and (env_key or cfg_has_own_key.get(pid)):
            providers.append({
                "id": pid,
                "label": plabel,
                "icon": "cloud",
                "connected": True,
                "models": cloud_configured,
                "default_model": cfg_default.get(pid) or cloud_configured[0],
            })

    return {"providers": providers}
