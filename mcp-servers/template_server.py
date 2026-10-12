#!/usr/bin/env python3
"""
SOCIS-AI-PT — Template MCP Server (HTTP transport)
FastAPI-based MCP server for [YOUR TOOL HERE]

Copy this file and customize it to add new MCP servers.
Replace ALL [PLACEHOLDERS] with your tool specifics.

To use this template:
1. Copy to {tool}_server.py (e.g., "waf_detector_server.py")
2. Update TOOLS list with your tool definitions
3. Implement handle_tool_X functions
4. Add docker-compose.yml entry
5. Register in backend/app/mcp/client.py
6. Start: python3 {tool}_server.py
"""

import json
import asyncio
import re
import subprocess
import logging
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from typing import Any, Optional

# ───────────────────────────────────────────────────────────
# CONFIGURATION - CUSTOMIZE THESE
# ───────────────────────────────────────────────────────────

TOOL_NAME = "[YOUR_TOOL_NAME]"              # e.g., "owasp-zap", "burp-suite"
MCP_PORT = 8105                              # Change to your port (8105-8119)
MCP_VERSION = "1.0"
SERVER_NAME = f"{TOOL_NAME}-mcp"

# Logging setup
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# ───────────────────────────────────────────────────────────
# TOOL DEFINITIONS - THIS IS YOUR "INTERFACE"
# ───────────────────────────────────────────────────────────
"""
Each tool needs:
1. name: Unique identifier for the tool
2. description: What the tool does (shown in UI)
3. inputSchema: JSON schema defining input parameters

The inputSchema follows JSON Schema standard:
- type: "object"
- properties: dict of parameter names → type/description
- required: list of required parameter names
"""

TOOLS = [
    {
        "name": "tool_1_name",
        "description": "Brief description of what this tool does. Include examples of input/output.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL or IP address to scan (e.g., https://example.com or 192.168.1.1)"
                },
                "aggressive": {
                    "type": "boolean",
                    "description": "Enable aggressive scanning (more thorough but slower)",
                    "default": False
                },
                "timeout": {
                    "type": "integer",
                    "description": "Scan timeout in seconds",
                    "default": 300
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "tool_2_name",
        "description": "Second tool description",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to results file to analyze"
                }
            },
            "required": ["file_path"]
        }
    },
    # Add more tools here
]

# FastAPI app setup
app = FastAPI(title=f"SOCIS {TOOL_NAME} MCP Server", docs_url=None)


# ───────────────────────────────────────────────────────────
# MCP PROTOCOL HANDLERS
# ───────────────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    """Health check endpoint for container orchestration"""
    return {
        "status": "healthy",
        "server": SERVER_NAME,
        "version": MCP_VERSION,
    }


@app.post("/")
async def handle_mcp_request(request: Request):
    """
    Main MCP request handler.
    Follows the Model Context Protocol specification.
    """
    try:
        data = await request.json()
        method = data.get("method")
        
        log.info(f"[MCP] Received request: {method}")
        
        # ─── tools/list: Return available tools
        if method == "tools/list":
            return JSONResponse({
                "tools": TOOLS
            })
        
        # ─── tools/call: Execute a tool
        elif method == "tools/call":
            tool_name = data.get("params", {}).get("name")
            arguments = data.get("params", {}).get("arguments", {})
            
            log.info(f"[MCP] Executing tool: {tool_name}")
            
            # Validate tool exists
            tool_exists = any(t["name"] == tool_name for t in TOOLS)
            if not tool_exists:
                return JSONResponse(
                    {"error": f"Unknown tool: {tool_name}"},
                    status_code=400
                )
            
            try:
                # Route to appropriate handler
                if tool_name == "tool_1_name":
                    result = await handle_tool_1(arguments)
                elif tool_name == "tool_2_name":
                    result = await handle_tool_2(arguments)
                else:
                    raise ValueError(f"No handler for tool: {tool_name}")
                
                log.info(f"[MCP] Tool {tool_name} completed successfully")
                return JSONResponse({
                    "result": result,
                    "tool": tool_name,
                    "success": True
                })
            
            except ValueError as e:
                log.warning(f"[MCP] Validation error: {e}")
                return JSONResponse(
                    {"error": str(e)},
                    status_code=400
                )
            except asyncio.TimeoutError:
                log.error(f"[MCP] Tool execution timeout: {tool_name}")
                return JSONResponse(
                    {"error": f"Tool execution timeout"},
                    status_code=504
                )
            except Exception as e:
                log.error(f"[MCP] Tool execution error: {e}")
                return JSONResponse(
                    {"error": str(e), "tool": tool_name},
                    status_code=500
                )
        
        else:
            return JSONResponse(
                {"error": f"Unknown method: {method}"},
                status_code=400
            )
    
    except json.JSONDecodeError:
        return JSONResponse(
            {"error": "Invalid JSON"},
            status_code=400
        )
    except Exception as e:
        log.error(f"[MCP] Unexpected error: {e}")
        return JSONResponse(
            {"error": str(e)},
            status_code=500
        )


# ───────────────────────────────────────────────────────────
# TOOL IMPLEMENTATIONS
# ───────────────────────────────────────────────────────────

async def handle_tool_1(args: dict) -> dict:
    """
    Implementation for tool_1_name.
    
    Steps:
    1. Validate input arguments
    2. Execute the actual tool/command
    3. Parse output
    4. Return structured result
    """
    
    # ─── Step 1: Input Validation
    target = args.get("target")
    timeout = args.get("timeout", 300)
    aggressive = args.get("aggressive", False)
    
    if not target:
        raise ValueError("'target' parameter is required")
    
    # Security: Validate target format
    # Use whitelist approach (only allow expected characters)
    if not re.match(r'^[a-zA-Z0-9.\-_:/?=&%#+@]+$', target):
        raise ValueError(f"Invalid target format: {target}")
    
    if timeout < 10 or timeout > 3600:
        raise ValueError("Timeout must be between 10 and 3600 seconds")
    
    # ─── Step 2: Build command
    # IMPORTANT: Always use list format, NOT string interpolation
    # This prevents command injection vulnerabilities
    cmd = [
        "your_tool_command",  # Replace with actual tool
        "--target", target,
        "--timeout", str(timeout),
    ]
    
    if aggressive:
        cmd.append("--aggressive")
    
    # ─── Step 3: Execute tool
    try:
        log.info(f"Executing: {' '.join(cmd)}")
        
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        # Wait with timeout
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout
        )
        
        # Decode output
        output = stdout.decode('utf-8', errors='ignore')
        error = stderr.decode('utf-8', errors='ignore') if stderr else None
        
        # ─── Step 4: Parse and structure output
        # This is where you transform raw tool output into structured JSON
        parsed_results = parse_tool_output(output)
        
        return {
            "success": True,
            "target": target,
            "findings": parsed_results,
            "raw_output": output[:1000],  # Include first 1000 chars
            "execution_time": timeout,
            "error": error
        }
    
    except asyncio.TimeoutError:
        log.error(f"Tool execution exceeded {timeout}s timeout")
        raise TimeoutError(f"Execution timeout after {timeout} seconds")
    
    except FileNotFoundError:
        raise ValueError(f"Tool 'your_tool_command' not found. Is it installed?")
    
    except Exception as e:
        log.error(f"Tool execution failed: {e}")
        raise


async def handle_tool_2(args: dict) -> dict:
    """
    Implementation for tool_2_name.
    
    This is a simpler example that processes a file.
    """
    
    file_path = args.get("file_path")
    
    if not file_path:
        raise ValueError("'file_path' parameter is required")
    
    # Prevent directory traversal attacks
    if ".." in file_path or file_path.startswith("/"):
        raise ValueError("Invalid file path")
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Parse and structure the file
        results = parse_results_file(content)
        
        return {
            "success": True,
            "file": file_path,
            "results": results,
            "summary": generate_summary(results)
        }
    
    except FileNotFoundError:
        raise ValueError(f"File not found: {file_path}")
    except Exception as e:
        raise ValueError(f"Error reading file: {e}")


# ───────────────────────────────────────────────────────────
# HELPER FUNCTIONS FOR OUTPUT PARSING
# ───────────────────────────────────────────────────────────

def parse_tool_output(raw_output: str) -> list[dict]:
    """
    Parse raw tool output into structured findings.
    
    This is tool-specific. Examples:
    - Parse JSON output: json.loads()
    - Parse CSV: csv.DictReader()
    - Parse text lines: string methods
    - Parse XML: xml.etree.ElementTree
    """
    
    findings = []
    
    # Example: Parse line-by-line output
    for line in raw_output.strip().split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        # Extract data based on your tool's output format
        # This is a placeholder
        finding = {
            "raw": line,
            "parsed": True
        }
        findings.append(finding)
    
    return findings


def parse_results_file(content: str) -> list[dict]:
    """Parse results from file content."""
    # Implement based on your file format
    try:
        return json.loads(content)
    except Exception:
        return [{"line": l} for l in content.strip().split('\n')]


def generate_summary(results: list[dict]) -> dict:
    """Generate a summary of findings."""
    return {
        "total_findings": len(results),
        "critical": len([r for r in results if r.get("severity") == "critical"]),
        "high": len([r for r in results if r.get("severity") == "high"]),
        "medium": len([r for r in results if r.get("severity") == "medium"]),
    }


# ───────────────────────────────────────────────────────────
# STARTUP
# ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info(f"Starting {SERVER_NAME} on port {MCP_PORT}")
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=MCP_PORT,
        log_level="info"
    )
