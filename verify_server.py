#!/usr/bin/env python3
"""Offline, assertion-based MCP verification; no scanners or target traffic.

    python verify_server.py                 # local Python server, temporary workspace
    python verify_server.py --json          # machine-readable result
    python verify_server.py --docker        # existing image, network disabled

A successful result proves protocol startup, tool registration, fail-closed scope,
and synthetic finding/report persistence. It does not validate the Kali image,
external tools, a lab assessment, or every adapter's safety boundary.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parent
REQUIRED_TOOLS = frozenset({
    "authorized_scope", "workspace_info", "nmap_scan", "http_request",
    "save_finding", "list_findings", "generate_report", "generate_h1_report",
})


class VerificationError(RuntimeError):
    """A protocol response did not satisfy a smoke-test assertion."""


def _require(condition: bool, message: str) -> None:
    # Do not use Python assert: verification must still run under python -O.
    if not condition:
        raise VerificationError(message)


def _text(result: Any) -> str:
    _require(not getattr(result, "isError", False), "MCP tool returned isError")
    return "\n".join(c.text for c in result.content if getattr(c, "type", "") == "text")


def _server_params(workspace: Path, *, docker: bool, image: str) -> StdioServerParameters:
    env = os.environ.copy()
    # Never inherit engagement scope or evidence credentials into a smoke test.
    env.update({
        "WORKSPACE": str(workspace), "KALI_TARGET_ALLOWLIST": "",
        "KALI_TARGET_DENYLIST": "", "ENGAGEMENT_ATTRIBUTION": "",
        "SCAN_TIMEOUT": "2", "HTTP_TIMEOUT": "2", "HTTP_MIN_INTERVAL": "0",
        "MAX_OUTPUT_CHARS": "20000", "MAX_OUTPUT_BYTES": "80000", "MAX_BODY_CHARS": "20000",
        "MAX_BODY_BYTES": "1048576", "HTTP_SAVE_BODY_EVIDENCE": "0",
        "MSF_HOST": "fixture.invalid", "MSF_PORT": "55553", "MSF_PASSWORD": "",
    })
    if not docker:
        return StdioServerParameters(
            command=sys.executable,
            args=[str(ROOT / "kali-mcp" / "kali_security_server.py")],
            env=env, cwd=str(ROOT),
        )
    args = ["run", "--rm", "-i", "--network", "none", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges"]
    # A temporary host workspace must be writable by the container on Linux.
    if hasattr(os, "getuid"):
        args += ["--user", f"{os.getuid()}:{os.getgid()}"]
    args += ["--mount", f"type=bind,source={workspace},target=/workspace",
             "-e", "WORKSPACE=/workspace", "-e", "KALI_TARGET_ALLOWLIST=",
             "-e", "KALI_TARGET_DENYLIST=", "-e", "ENGAGEMENT_ATTRIBUTION=",
             "-e", "SCAN_TIMEOUT=2", "-e", "HTTP_TIMEOUT=2", image]
    return StdioServerParameters(command="docker", args=args, env=env, cwd=str(ROOT))


async def _exercise(params: StdioServerParameters, workspace: Path) -> dict[str, Any]:
    checks: list[str] = []
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            names = [tool.name for tool in listed.tools]
            _require(REQUIRED_TOOLS.issubset(names), "Required tools are missing")
            _require(len(names) == len(set(names)), "Tool names are not unique")
            for tool in listed.tools:
                if tool.name in REQUIRED_TOOLS:
                    _require(tool.inputSchema.get("type") == "object",
                             f"{tool.name} has an invalid input schema")
            checks.append("MCP initialization and required tool schemas")
            scope = _text(await session.call_tool("authorized_scope", {}))
            _require("No scope configured" in scope, "Smoke server inherited target scope")
            for name, args in (
                ("nmap_scan", {"target": "example.invalid"}),
                ("http_request", {"url": "https://example.invalid/"}),
            ):
                result = _text(await session.call_tool(name, args))
                _require(result.startswith("[blocked]"), f"{name} did not fail closed")
            checks.append("No-scope CLI and HTTP requests blocked")
            info = _text(await session.call_tool("workspace_info", {}))
            _require("writable=True" in info, "Temporary workspace is not writable")
            _require("No findings" in _text(await session.call_tool("list_findings", {})),
                     "Temporary workspace was not empty")
            for title, severity in (("Synthetic low finding", "low"),
                                    ("Synthetic high finding", "high")):
                saved = _text(await session.call_tool("save_finding", {
                    "title": title, "severity": severity, "target": "fixture.invalid",
                    "detail": "Offline fixture; not a discovered vulnerability.",
                    "evidence": "SYNTHETIC EVIDENCE ONLY", "remediation": "Fixture remediation.",
                }))
                _require("Saved finding:" in saved, "Finding was not saved")
            report = _text(await session.call_tool("generate_report", {
                "title": "Offline protocol verification",
            }))
            _require("Total findings: 2" in report, "Report omitted synthetic findings")
            _require(report.index("Synthetic high finding") < report.index("Synthetic low finding"),
                     "Report is not severity ordered")
            h1_report = _text(await session.call_tool("generate_h1_report", {}))
            _require("Synthetic high finding" in h1_report, "Detailed report selected wrong finding")
            checks.append("Synthetic finding save and both report formats")

    # A new server process must recover findings from the same workspace.
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            saved_text = _text(await session.call_tool("list_findings", {}))
            rows = [json.loads(line) for line in saved_text.splitlines() if line.strip()]
            _require({row["title"] for row in rows} == {
                "Synthetic low finding", "Synthetic high finding",
            }, "Finding persistence failed across server restart")
    _require((workspace / "report.md").is_file(), "Report file was not persisted")
    _require("SYNTHETIC EVIDENCE ONLY" in (workspace / "report.md").read_text(encoding="utf-8"),
             "Persisted report lost fixture evidence")
    _require(len(list(workspace.glob("h1-*.md"))) == 1, "Detailed report was not persisted")
    _require(not (workspace / "output").exists(), "Blocked CLI request unexpectedly produced evidence")
    checks.append("Persistence across real server restart and disk verification")
    return {"ok": True, "tool_count": len(names), "checks": checks}


async def verify(*, docker: bool = False, image: str = "kali-security-mcp-server:latest",
                 timeout: float = 90) -> dict[str, Any]:
    """Run only synthetic local operations and clean up the temporary workspace."""
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="red-mcp-verify-") as tmp:
        workspace = Path(tmp)
        params = _server_params(workspace, docker=docker, image=image)
        async with asyncio.timeout(timeout):
            result = await _exercise(params, workspace)
    result.update({"transport": "docker-stdio" if docker else "python-stdio",
                   "elapsed_seconds": round(time.monotonic() - started, 2)})
    return result


def _positive_seconds(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if not 0 < seconds <= 300:
        raise argparse.ArgumentTypeError("timeout must be greater than 0 and at most 300 seconds")
    return seconds


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--docker", action="store_true", help="Verify an existing image with network disabled")
    parser.add_argument("--image", default="kali-security-mcp-server:latest")
    parser.add_argument("--timeout", type=_positive_seconds, default=90, help="Overall timeout in seconds (default: 90)")
    parser.add_argument("--json", action="store_true", help="Print a machine-readable result")
    args = parser.parse_args()
    try:
        result = asyncio.run(verify(docker=args.docker, image=args.image, timeout=args.timeout))
    except (Exception, KeyboardInterrupt) as exc:
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc) or type(exc).__name__}))
        else:
            print(f"FAIL: {str(exc) or type(exc).__name__}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result))
    else:
        print(f"PASS: {result['tool_count']} tools registered ({result['transport']})")
        for check in result["checks"]:
            print(f"  PASS: {check}")
        print("Not tested: Kali image build, external tools, live lab or third-party targets.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
