"""
SOCIS-AI-PT — Custom Exception Handlers
Standardized error responses for the API.
"""

from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse


class SocisException(Exception):
    """Base exception for SOCIS-AI-PT."""
    def __init__(self, message: str, status_code: int = 500, detail: dict = None):
        self.message = message
        self.status_code = status_code
        self.detail = detail or {}
        super().__init__(self.message)


class ScanNotFoundError(SocisException):
    def __init__(self, scan_id: str):
        super().__init__(f"Scan '{scan_id}' not found", status_code=404)


class ProjectNotFoundError(SocisException):
    def __init__(self, project_id: str):
        super().__init__(f"Project '{project_id}' not found", status_code=404)


class ToolExecutionError(SocisException):
    def __init__(self, tool_name: str, message: str):
        super().__init__(f"Tool '{tool_name}' failed: {message}", status_code=500)


class LLMConnectionError(SocisException):
    def __init__(self, provider: str, message: str):
        super().__init__(f"LLM provider '{provider}' error: {message}", status_code=502)


class MCPServerError(SocisException):
    def __init__(self, server_name: str, message: str):
        super().__init__(f"MCP server '{server_name}' error: {message}", status_code=502)


class InsufficientPermissionError(SocisException):
    def __init__(self, permission: str):
        super().__init__(f"Insufficient permissions: {permission}", status_code=403)


async def socis_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Global exception handler for SOCIS exceptions."""
    if isinstance(exc, SocisException):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": True,
                "message": exc.message,
                "detail": exc.detail,
            },
        )
    # Fallback for non-SOCIS exceptions
    return JSONResponse(
        status_code=500,
        content={
            "error": True,
            "message": "Internal server error",
            "detail": {},
        },
    )
