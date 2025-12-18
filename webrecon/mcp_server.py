"""WEBRECON MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from webrecon.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-webrecon[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-webrecon[mcp]'")
        return 1
    app = FastMCP("webrecon")

    @app.tool()
    def webrecon_scan(target: str) -> str:
        """Fingerprint web tech/CMS/frameworks from headers + body. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
