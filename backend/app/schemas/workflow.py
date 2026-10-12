"""
SOCIS-AI-PT — Workflow Definition Pydantic Schemas
"""

from __future__ import annotations
import uuid
from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field


# ── Node / Edge primitives ────────────────────────────────────────────────────

class NodePosition(BaseModel):
    x: float = 0.0
    y: float = 0.0


class WorkflowNodeData(BaseModel):
    """
    Flexible data bag for all node types.
    Tool node: tool, timeout, flags, port_filter
    LLM node:  provider, model, remote_url, prompt, output_key
    Condition: expression
    Start:     target, project_id
    Report:    template
    """
    model_config = {"extra": "allow"}

    label: Optional[str] = None
    # tool node
    tool: Optional[str] = None
    timeout: Optional[int] = None
    flags: Optional[str] = None
    port_filter: Optional[list[int]] = None
    # llm node
    provider: Optional[str] = None
    model: Optional[str] = None
    remote_url: Optional[str] = None
    prompt: Optional[str] = None
    output_key: Optional[str] = None
    # condition node
    expression: Optional[str] = None
    # report node
    template: Optional[str] = None
    # start node
    target: Optional[str] = None
    project_id: Optional[str] = None
    # nikto fields
    nikto_url: Optional[str] = None
    nikto_action: Optional[str] = None
    nikto_tuning: Optional[str] = None
    nikto_port: Optional[int] = None
    nikto_ssl: Optional[bool] = None
    # masscan fields
    masscan_action: Optional[str] = None
    masscan_ports: Optional[str] = None
    masscan_rate: Optional[int] = None
    masscan_top: Optional[int] = None
    masscan_cidr: Optional[str] = None
    # wpscan fields
    wpscan_url: Optional[str] = None
    wpscan_action: Optional[str] = None
    wpscan_enumerate: Optional[str] = None
    wpscan_api_token: Optional[str] = None
    wpscan_detection: Optional[str] = None
    wpscan_username_wordlist: Optional[str] = None
    wpscan_password_wordlist: Optional[str] = None
    # jwt fields
    jwt_token: Optional[str] = None
    jwt_action: Optional[str] = None
    jwt_secret: Optional[str] = None
    jwt_algorithm: Optional[str] = None
    jwt_claims: Optional[dict] = None
    jwt_wordlist: Optional[str] = None
    # gobuster fields
    gobuster_mode: Optional[str] = None
    gobuster_url: Optional[str] = None
    gobuster_wordlist: Optional[str] = None
    gobuster_extensions: Optional[str] = None
    gobuster_domain: Optional[str] = None


class WorkflowNode(BaseModel):
    id: str
    type: str  # "start" | "tool" | "llm" | "condition" | "report"
    position: NodePosition = Field(default_factory=NodePosition)
    data: WorkflowNodeData = Field(default_factory=WorkflowNodeData)


class WorkflowEdge(BaseModel):
    id: str
    source: str
    target: str
    sourceHandle: Optional[str] = None   # "yes" / "no" for condition nodes
    targetHandle: Optional[str] = None


# ── Default LLM config ────────────────────────────────────────────────────────

class WorkflowDefaultLLM(BaseModel):
    provider: str = "ollama_remote"         # ollama_remote | openai | anthropic | openrouter | grok | mistral
    model: str = "qwen2.5:7b"
    remote_url: Optional[str] = None


# ── CRUD schemas ──────────────────────────────────────────────────────────────

class WorkflowDefinitionCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    project_id: Optional[uuid.UUID] = None
    nodes: list[dict[str, Any]] = Field(default_factory=list)
    edges: list[dict[str, Any]] = Field(default_factory=list)
    default_llm: Optional[WorkflowDefaultLLM] = None


class WorkflowDefinitionUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    project_id: Optional[uuid.UUID] = None
    nodes: Optional[list[dict[str, Any]]] = None
    edges: Optional[list[dict[str, Any]]] = None
    default_llm: Optional[WorkflowDefaultLLM] = None


class WorkflowRunRequest(BaseModel):
    """Parameters to override when running a workflow."""
    target: Optional[str] = None       # override start node target
    project_id: Optional[str] = None   # accept string, convert to UUID in endpoint
    scope_override_reason: Optional[str] = None   # administrators only: authorize an out-of-scope target (audited)


# ── Response schemas ──────────────────────────────────────────────────────────

class WorkflowCreatorOut(BaseModel):
    model_config = {"from_attributes": True}
    id: uuid.UUID
    username: str
    email: str


class WorkflowDefinitionOut(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    name: str
    description: Optional[str]
    project_id: Optional[uuid.UUID]
    created_by: uuid.UUID
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    default_llm: Optional[dict[str, Any]]
    created_at: datetime
    updated_at: datetime


class WorkflowListResponse(BaseModel):
    workflows: list[WorkflowDefinitionOut]
    total: int
