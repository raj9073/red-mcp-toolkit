# RED MCP Toolkit

**Scoped security-tool orchestration, evidence handling and reporting over the Model Context Protocol.**

RED MCP connects an MCP client to 73 registered security-tool adapters and analysis
helpers. It combines explicit target scope, bounded command execution, an HTTP client
with credential-aware redirect handling, and a persistent findings/reporting workflow.
The toolkit image runs as a non-root user; the Python-only verification path needs
neither Docker nor a live target.

> **Authorized use only.** Use active tooling only on systems you own or have explicit
> permission to assess. The sample configuration starts with an empty allowlist.
> Scope checks complement—rather than replace—network isolation and engagement rules.
> Read [SECURITY.md](SECURITY.md) before enabling active use.

## Highlights

- **Explicit scope:** shared allow/deny checks and constrained options reject
  unsupported targets and command overrides before invocation.
- **Bounded execution:** the POSIX runner limits captured output while a command is
  running, cleans up process groups on timeout/overflow, and reports exit status.
- **HTTP safeguards:** TLS verification by default, per-hop scope checks,
  cross-origin credential stripping, and explicit incomplete-response handling.
- **Evidence discipline:** private HTTP metadata by default, opt-in body retention,
  known-credential masking, and a persistent workspace for reviewable findings.
- **Reporting:** synthetic or operator-recorded findings feed severity-ordered
  Markdown reports and a detailed disclosure-report format.
- **Reproducible verification:** 84 automated checks cover boundaries, process
  handling, HTTP behavior, and real MCP stdio startup/report persistence. Four
  HTTP integration tests use an actual loopback-only fixture server.

## Get started: offline verification

Use Python 3.12 on Linux/POSIX for the complete regression suite:

```sh
git clone https://github.com/raj9073/red-mcp-toolkit.git
cd red-mcp-toolkit
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-test.txt
python verify_server.py --json
python -m unittest discover -s tests -v
```

The verifier starts the real MCP server, checks empty-scope blocking, saves synthetic
findings, generates both report formats, and confirms persistence after a restart.
It uses a temporary workspace and does not launch scanners or send target requests.
The regression suite adds synthetic child processes, deterministic mocks and local
HTTP fixtures. [Testing documentation](docs/TESTING.md) explains the exact coverage.

## Use the toolkit in an authorized lab

Docker is required for the Kali/tooling image:

```sh
docker build -t kali-security-mcp-server:latest ./kali-mcp

# Optional: start the included practice target.
docker compose -f ./lab/docker-compose.yml up -d

# Check an already-built image without target networking.
python verify_server.py --docker
```

The practice web target is published on `127.0.0.1:8080`. The MCP sample configuration
uses the `redlab` network and the portable Docker volume `red-mcp-workspace`.
If you skip the practice compose setup, create or select the Docker network before
using the sample configuration (for example, `docker network create redlab`); update
`.mcp.json` if you choose a different network.
It starts with **no authorized targets** and drops extra container capabilities.
Set only your approved hosts/networks in `KALI_TARGET_ALLOWLIST`, configure any
required attribution, then enable the `kali-security` server in your MCP client.
Raw-socket features require a separate, reviewed capability choice.

See the [tool reference](kali-mcp/README.md) and [lab setup](lab/README.md) for the
individual adapters, configuration and practice services.

## Architecture

```text
MCP client → stdio server → scope / validation → tool adapters
                              │                    │
                              └── evidence + findings + reports
```

A client starts one server/container session; tool calls share that session.
The configured workspace volume persists after the container exits. The project
includes adapters for discovery, web/API analysis, TLS, SMB/AD, cloud/IaC inspection,
screenshots and reporting. Registration does not mean every external tool has been
exercised in the offline suite.

## Repository guide

| Path | Purpose |
|---|---|
| `kali-mcp/kali_security_server.py` | MCP server and tool adapters |
| `kali-mcp/Dockerfile` | Non-root Kali toolkit image definition |
| `.mcp.json` | Portable, deny-by-default client configuration |
| `tests/` | Boundary, HTTP and protocol regression tests |
| `verify_server.py` | Real offline MCP workflow verifier |
| `docs/TESTING.md` | Commands, coverage and reproducibility |
| `SECURITY.md` | Authorization, evidence policy and trust boundaries |
| `lab/` | Explicitly owned practice-service definitions |

## Verification and responsible use

The included tests and local verification cover Python runtime behavior, real MCP protocol flows
and synthetic/loopback fixtures. Docker image builds and individual external-tool
integrations are separate checks. Treat scanner output as evidence to review—not an
automatically confirmed vulnerability. Review sensitive output before sharing and
apply engagement-specific storage, retention and network controls.

## Development and license

An AI-assisted integration and safety-engineering project maintained by
[raj9073](https://github.com/raj9073). MIT-licensed source; see [LICENSE](LICENSE).
Third-party tools and images retain their respective licenses.
