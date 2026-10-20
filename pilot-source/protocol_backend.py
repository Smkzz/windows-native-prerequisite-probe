"""Synthetic MCP backend protocol fixture, not production winfs-mcp."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import site
import sys

async def run(config):
    config = Path(config)
    root = config.parents[2]
    if (re.fullmatch(r"C:\\LocalControlRegressionMcp-[a-f0-9]{32}", str(root)) is None or
        config != root / "control" / "state" / "winfs-pilot.json"):
        raise RuntimeError("FIXED_BACKEND_CONFIG_REQUIRED")
    site.addsitedir(str(root / "venv" / "Lib" / "site-packages"))
    from mcp.server.lowlevel import Server
    from mcp.server.stdio import stdio_server
    from mcp import types
    raw = json.loads(config.read_text())
    subject = root / "fixture" / "project"
    if raw["allowedRoots"] != [str(subject)]:
        raise RuntimeError("BACKEND_FIXTURE_ROOT_MISMATCH")
    report = root / "control" / "backend-report.json"
    count = 0
    report.write_text(json.dumps({"fixture": "PROTOCOL_ONLY", "read_calls": count}))
    server = Server("GenericBackendProtocolFixture", version="1")
    @server.list_tools()
    async def tools():
        return [types.Tool(name=name, description="Synthetic protocol fixture",
            inputSchema={"type":"object"}) for name in ("read","write","edit_file","list","stat")]
    @server.call_tool()
    async def call(name, arguments):
        nonlocal count
        # Only the one public synthetic positive-control file is served.
        path = Path(arguments.get("path", ""))
        if name != "read" or path != subject / "probe.txt":
            return types.CallToolResult(content=[types.TextContent(type="text",
                text=json.dumps({"code":"FIXTURE_OPERATION_DENIED"}))], isError=True)
        for part in (path, *path.parents):
            if part.exists() and part.lstat().st_file_attributes & 0x400:
                raise RuntimeError("FIXTURE_REPARSE_REFUSED")
        text = path.read_text(encoding="utf-8")
        count += 1
        report.write_text(json.dumps({"fixture": "PROTOCOL_ONLY", "read_calls": count}))
        value = {"content":text,"truncated":False,"bytes_returned":len(text.encode()),
                 "lines_returned":len(text.splitlines())}
        return types.CallToolResult(content=[types.TextContent(type="text",text=json.dumps(value))],
                                    structuredContent=value, isError=False)
    async with stdio_server() as streams:
        await server.run(*streams, server.create_initialization_options())

if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--config":
        raise RuntimeError("FIXED_BACKEND_ARGUMENTS_REQUIRED")
    asyncio.run(run(sys.argv[2]))
