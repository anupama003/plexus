"""
MCP server for plexus's graph tools (stdio).

Tools come straight from core.registry, so the chat, this server and the tests
share one definition of every tool. The server acts as one person (MCP_ACTOR)
on one incident (MCP_INCIDENT); permissions and memory apply as in the app.

    claude mcp add plexus -- /abs/path/.venv/bin/python /abs/path/backend/mcp_server.py
"""
import json
import os

import anyio
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from core import access, registry

ACTOR = os.getenv("MCP_ACTOR", "Mei Tanaka")
INCIDENT = os.getenv("MCP_INCIDENT", "mcp-default")
FIELDS = ("status", "found", "data", "paths", "touched", "cypher", "ms")


async def list_tools(ctx, params):
    return types.ListToolsResult(tools=[
        types.Tool(name=s["name"], description=s["description"], input_schema=s["input_schema"])
        for s in registry.TOOL_SPECS])


async def call_tool(ctx, params):
    result = registry.run_tool(params.name, params.arguments or {}, INCIDENT, access.get_person(ACTOR))
    payload = json.dumps({k: result.get(k) for k in FIELDS}, default=str)
    return types.CallToolResult(content=[types.TextContent(type="text", text=payload)],
                                is_error=result["status"] in ("error", "invalid"))


server = Server("plexus", instructions="CRA incident desk over a FalkorDB graph. Start with blast_radius for "
                                       "'are we affected?'. If a tool returns not_found, say it is not in the graph.",
                on_list_tools=list_tools, on_call_tool=call_tool)


async def main():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    anyio.run(main)
