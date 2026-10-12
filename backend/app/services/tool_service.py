"""
SOCIS-AI-PT — Tool Service
Async tool execution for penetration testing tools.
Extended from the original tools.py with async support and 18 tools.
"""

import asyncio
import time
from typing import Dict, Optional, List
from enum import Enum

from app.config import settings


class ToolCategory(str, Enum):
    RECON = "recon"
    VULN_SCAN = "vuln_scan"
    EXPLOIT = "exploit"
    OSINT = "osint"


# ─── Tool Registry ───────────────────────────────────────────

TOOL_REGISTRY = {
    # Reconnaissance
    "nmap": {"category": ToolCategory.RECON, "timeout": settings.TOOL_TIMEOUT_NMAP,
             "description": "Network port scanner and service detection"},
    "whois": {"category": ToolCategory.RECON, "timeout": 30,
              "description": "Domain registration lookup"},
    "whatweb": {"category": ToolCategory.RECON, "timeout": 60,
                "description": "Web technology fingerprinting"},
    "curl": {"category": ToolCategory.RECON, "timeout": 20,
             "description": "HTTP header analysis"},
    "dig": {"category": ToolCategory.RECON, "timeout": 15,
            "description": "DNS record resolution"},
    "subfinder": {"category": ToolCategory.RECON, "timeout": 120,
                  "description": "Subdomain enumeration"},
    "httpx": {"category": ToolCategory.RECON, "timeout": 120,
              "description": "HTTP probing and fingerprinting"},
    "masscan": {"category": ToolCategory.RECON, "timeout": 120,
                "description": "Fast port scanner"},
    "feroxbuster": {"category": ToolCategory.RECON, "timeout": 300,
                    "description": "Directory and file brute-forcer"},
    "gobuster": {"category": ToolCategory.RECON, "timeout": 300,
                 "description": "Directory/DNS brute-forcer"},
    "ffuf": {"category": ToolCategory.RECON, "timeout": 300,
             "description": "Fast web fuzzer"},
    "dirb": {"category": ToolCategory.RECON, "timeout": 300,
             "description": "URL brute-forcer"},
    # Vulnerability Scanning
    "nikto": {"category": ToolCategory.VULN_SCAN, "timeout": settings.TOOL_TIMEOUT_NIKTO,
              "description": "Web server vulnerability scanner"},
    "nuclei": {"category": ToolCategory.VULN_SCAN, "timeout": settings.TOOL_TIMEOUT_NUCLEI,
               "description": "Template-based vulnerability scanner"},
    "testssl": {"category": ToolCategory.VULN_SCAN, "timeout": 300,
                "description": "TLS/SSL configuration tester"},
    "wpscan": {"category": ToolCategory.VULN_SCAN, "timeout": 300,
               "description": "WordPress vulnerability scanner"},
    # Exploitation
    "sqlmap": {"category": ToolCategory.EXPLOIT, "timeout": 600,
               "description": "Automated SQL injection testing"},
}

ALLOWED_TOOLS = set(TOOL_REGISTRY.keys())


class ToolService:
    """Async tool execution service."""

    async def run_tool(self, command: List[str], timeout: int = None) -> Dict:
        """Execute a tool command asynchronously."""
        tool_name = command[0].split("/")[-1] if command else "unknown"
        timeout = timeout or TOOL_REGISTRY.get(tool_name, {}).get("timeout", settings.TOOL_TIMEOUT_DEFAULT)

        start_time = time.time()
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )
            duration_ms = int((time.time() - start_time) * 1000)

            output = stdout.decode("utf-8", errors="replace").strip()
            errors = stderr.decode("utf-8", errors="replace").strip()

            return {
                "tool": tool_name,
                "output": output if output else errors if errors else "[!] Tool returned no output.",
                "exit_code": process.returncode,
                "duration_ms": duration_ms,
                "success": process.returncode == 0,
            }
        except asyncio.TimeoutError:
            return {
                "tool": tool_name,
                "output": f"[!] Timed out after {timeout}s",
                "exit_code": -1,
                "duration_ms": int((time.time() - start_time) * 1000),
                "success": False,
            }
        except FileNotFoundError:
            return {
                "tool": tool_name,
                "output": f"[!] Tool not found: {command[0]}",
                "exit_code": -1,
                "duration_ms": 0,
                "success": False,
            }
        except Exception as e:
            return {
                "tool": tool_name,
                "output": f"[!] Error: {str(e)}",
                "exit_code": -1,
                "duration_ms": int((time.time() - start_time) * 1000),
                "success": False,
            }

    async def run_nmap(self, target: str, flags: str = "-sV -sC -T4 --open") -> Dict:
        """Run nmap with customizable flags."""
        cmd = ["nmap"] + flags.split() + [target]
        return await self.run_tool(cmd, TOOL_REGISTRY["nmap"]["timeout"])

    async def run_whois(self, target: str) -> Dict:
        return await self.run_tool(["whois", target], 30)

    async def run_whatweb(self, target: str) -> Dict:
        return await self.run_tool(["whatweb", "-a", "3", target], 60)

    async def run_curl_headers(self, target: str) -> Dict:
        http = await self.run_tool(
            ["curl", "-sI", "--max-time", "10", "--location", f"http://{target}"], 20
        )
        https = await self.run_tool(
            ["curl", "-sI", "--max-time", "10", "--location", "-k", f"https://{target}"], 20
        )
        return {
            "tool": "curl",
            "output": f"[HTTP Headers]\n{http['output']}\n\n[HTTPS Headers]\n{https['output']}",
            "duration_ms": http["duration_ms"] + https["duration_ms"],
            "success": True,
        }

    async def run_dig(self, target: str) -> Dict:
        results = {}
        for rtype in ["A", "MX", "NS", "TXT"]:
            r = await self.run_tool(["dig", "+short", rtype, target], 15)
            results[rtype] = r["output"]
        output = "\n".join(f"[{k} Records]\n{v}" for k, v in results.items())
        return {"tool": "dig", "output": output, "duration_ms": 0, "success": True}

    async def run_nikto(self, target: str) -> Dict:
        return await self.run_tool(["nikto", "-h", target, "-nointeractive"], TOOL_REGISTRY["nikto"]["timeout"])

    async def run_nuclei(self, target: str, templates: str = None) -> Dict:
        cmd = ["nuclei", "-target", target]
        if templates:
            cmd.extend(["-t", templates])
        return await self.run_tool(cmd, TOOL_REGISTRY["nuclei"]["timeout"])

    async def run_by_command(self, command_str: str) -> Dict:
        """Execute a tool by raw command string (with allowlist enforcement)."""
        parts = command_str.strip().split()
        if not parts:
            return {"tool": "unknown", "output": "[!] Empty command.", "success": False}

        tool = parts[0].lower().split("/")[-1]
        if tool not in ALLOWED_TOOLS:
            return {"tool": tool, "output": f"[!] Tool '{tool}' is not permitted. Allowed: {ALLOWED_TOOLS}", "success": False}

        return await self.run_tool(parts)

    async def run_default_recon(self, target: str) -> Dict[str, Dict]:
        """Run standard recon pipeline (nmap, whois, whatweb, curl, dig)."""
        tasks = {
            "nmap": self.run_nmap(target),
            "whois": self.run_whois(target),
            "whatweb": self.run_whatweb(target),
            "curl_headers": self.run_curl_headers(target),
            "dig": self.run_dig(target),
        }
        results = {}
        for name, coro in tasks.items():
            results[name] = await coro
        return results

    @staticmethod
    def format_for_llm(results: Dict[str, Dict]) -> str:
        """Flatten tool results into a single string for LLM context."""
        output = ""
        for tool, data in results.items():
            output += f"\n{'=' * 50}\n"
            output += f"[ {tool.upper()} OUTPUT ]\n"
            output += f"{'=' * 50}\n"
            output += data.get("output", "").strip() + "\n"
        return output


# Singleton
tool_service = ToolService()
