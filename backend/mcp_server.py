"""NECROMANCER MCP server (stdio). Start it with ``uv run python -m mcp_server`` from ``backend/``.

Tools: exhume, autopsy, resurrect, prove, gate. They work on config text passed by the client,
process it in memory and make no network calls. stdout carries the MCP protocol, so anything
else must go to stderr.
"""

from __future__ import annotations

import logging
import sys

from mcp.server.fastmcp import FastMCP

from necro import mcp_tools
from necro.version import __version__


def build_server() -> FastMCP:
    server = FastMCP("necromancer", instructions=f"NECROMANCER {__version__}")
    for tool in mcp_tools.TOOLS:
        server.add_tool(tool, name=tool.__name__, description=tool.__doc__)
    return server


def main() -> None:
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    build_server().run(transport="stdio")


if __name__ == "__main__":
    main()
