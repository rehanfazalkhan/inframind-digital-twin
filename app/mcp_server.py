from __future__ import annotations

from .config import Settings
from .service import InfraMindService


def create_mcp_server(service: InfraMindService):
    """Exposes only bounded read-only topology tools through MCP."""
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("InfraMind Read-Only Cloud Gateway")

    @server.tool()
    def list_twins() -> list[dict]:
        """List the most recent discovered cloud digital twins."""
        return [twin.model_dump(mode="json", include={"id", "provider", "scope", "status", "created_at"}) for twin in service.repository.recent()]

    @server.tool()
    def topology_summary(twin_id: str) -> dict:
        """Return graph metadata and deterministic findings for a specific twin."""
        twin = service.repository.get(twin_id)
        if not twin:
            return {"error": "Twin not found"}
        return {"nodes": [node.model_dump() for node in twin.nodes], "edges": [edge.model_dump() for edge in twin.edges], "findings": [finding.model_dump(mode="json") for finding in twin.findings]}

    @server.tool()
    def calculate_change_impact(twin_id: str, resource_id: str) -> dict:
        """Calculate downstream blast radius for a proposed resource change. This never performs a mutation."""
        try:
            return service.blast_radius(twin_id, resource_id).model_dump()
        except KeyError:
            return {"error": "Twin or resource not found"}

    return server


if __name__ == "__main__":
    create_mcp_server(InfraMindService(Settings.from_environment())).run(transport="stdio")
