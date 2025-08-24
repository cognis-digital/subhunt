"""SUBHUNT MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from subhunt.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-subhunt[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-subhunt[mcp]'")
        return 1
    app = FastMCP("subhunt")

    @app.tool()
    def subhunt_scan(target: str) -> str:
        """Aggregate & dedupe subdomain enumeration from multiple sources. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
