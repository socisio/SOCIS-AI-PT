"""Parse the open-port lines of nmap's normal output (pure: unit-tested, no network).

A previous version of this regex used `\\s+` between the fields. Under re.MULTILINE `\\s` also matches a NEWLINE, so for a port whose
service has no version string (for example `554/tcp open rtsp?`) the optional version group swallowed the NEXT LINE: the following port
was reported inside the previous port's "version" and never appeared as a port of its own (a real scan lost port 2869 this way).
Fields are now separated by spaces/tabs only, so a match can never cross a line.
"""
import re
from typing import Dict, List

_PORT_LINE = re.compile(r"^(\d+)/(\w+)[ \t]+open[ \t]+(\S+)(?:[ \t]+(.+))?$", re.MULTILINE)


def parse_open_ports(output: str) -> List[Dict]:
    """[{port, protocol, service, version}] for every `PORT/proto open service [version]` line, in the order nmap printed them."""
    text = (output or "").replace("\r\n", "\n").replace("\r", "\n")
    ports: List[Dict] = []
    for m in _PORT_LINE.finditer(text):
        port, proto, service, version = m.groups()
        ports.append({"port": int(port), "protocol": proto, "service": service, "version": (version or "").strip()})
    return ports
