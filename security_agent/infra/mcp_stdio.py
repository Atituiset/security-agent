"""Local MCP stdio transport to the authenticated, allowlisted tool bridge."""
import asyncio
import json
import os
from urllib.request import Request, urlopen
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent, ListToolsResult, CallToolResult


def rpc(path, data):
    request = Request(os.environ['SECURITY_TOOL_URL'] + path, data=json.dumps(data).encode(),
                      headers={'Authorization': 'Bearer ' + os.environ['SECURITY_TOOL_TOKEN'], 'Content-Type': 'application/json'})
    with urlopen(request, timeout=60) as response:
        return json.load(response)


async def main():
    async def list_tools(context, params):
        return ListToolsResult(tools=[Tool(name=t['name'], description=t['description'], inputSchema=t['schema']) for t in rpc('/list', {})])
    async def call_tool(context, params):
        result = await asyncio.to_thread(rpc, '/call', {'name': params.name, 'arguments': params.arguments or {}})
        return CallToolResult(content=[TextContent(type='text', text=json.dumps(result))])
    server = Server('security-tools', on_list_tools=list_tools, on_call_tool=call_tool)
    async with stdio_server() as streams:
        await server.run(*streams, server.create_initialization_options())


if __name__ == '__main__':
    asyncio.run(main())
