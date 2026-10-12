"""
SOCIS-AI-PT — Custom Example Plugin
"""

import asyncio
from app.services.tools.base import BaseSecurityTool

class ExampleCustomScanner(BaseSecurityTool):
    """An example custom security tool that can be dropped into the plugins folder."""
    
    id = "example_scanner"
    name = "Example Custom Scanner"
    description = "Demonstration of a dynamically loaded custom security tool."
    binary_path = "echo"  # Fake binary
    
    async def run(self, target: str, **kwargs) -> dict:
        self.logger.info(f"Running custom scanner against {target}")
        
        proc = await asyncio.create_subprocess_exec(
            self.binary_path, "VULN_FOUND: Mock vulnerability in " + target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        output = stdout.decode()
        
        # Fake parsing logic
        if "VULN_FOUND" in output:
            vuln = self.create_vulnerability(
                name="Mock Custom Vulnerability",
                description="This is a dynamically loaded plugin demonstrating a mocked finding.",
                severity="low",
            )
            self.add_vulnerability(vuln)
            
        return self.get_results(output)
