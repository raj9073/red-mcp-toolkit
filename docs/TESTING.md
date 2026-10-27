# Offline verification and coverage

Run the full suite from the repository root on Linux/POSIX with Python 3.12 in a private virtual environment:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-test.txt
python -m unittest discover -s tests -v
python verify_server.py --json
```

The command runner's process-group checks target Linux/POSIX. Native Windows can
run the offline protocol verifier, but the complete native Windows suite has not
been validated; use a Linux environment for the full regression gate.

The suite uses Python's standard-library `unittest`; pytest and the Kali image are
not required. HTTP transport integration uses an ephemeral loopback-only synthetic
server; no external target is contacted. Other HTTP cases use deterministic mocks.
`requirements-test.txt` includes the same pinned direct Python dependencies as the
production server, so CI exercises dependency resolution and imports too. Transitive
dependencies and the Kali image are not fully locked. MCP stays on the tested 1.x
API: MCP 2.x removed `mcp.server.fastmcp`, so upgrading requires an explicit migration,
not a wider version range. Changing production pins must rerun the full offline suite.

## What the protocol verifier establishes

`verify_server.py` uses the installed MCP SDK as a real client of a separate
`kali_security_server.py` process. It does not stub FastMCP or call tool functions
in place of protocol messages. It checks:

1. MCP initialization, unique registered names and required tool availability.
2. Empty-scope `nmap_scan` and `http_request` calls return `[blocked]`.
3. Workspace access, two synthetic findings, severity-ordered Markdown reporting
   and the detailed report format.
4. A fresh server process can read those persisted findings, and the expected
   report files contain the fixture evidence.

The verifier creates a temporary workspace, overrides inherited allow/deny lists
and attribution, and removes the fixture files on completion. Its fixture domains
end in `.invalid`. No CLI scanner is executed and no target HTTP request is made.
The regression suite deliberately tests a contaminated parent environment to catch
accidental inheritance of scope. Verification uses explicit exception-based checks,
not `assert`, so `python -O` does not disable checks. A failing check, startup error
or timeout results in a nonzero exit status.

The 90-second default protocol budget can be changed with `--timeout` (maximum
300 seconds). Cold SDK imports and process cleanup can add time outside the async budget; the
regression suite gives its verifier subprocess an additional 120-second outer
timeout. This keeps all assertions while allowing loaded CI/cloud startup.
Server diagnostics stay on stderr; `--json` emits one result object on stdout.

## Focused regression coverage

The suite also covers scope allow/deny and input boundaries, bounded child-process
output and timeout behavior, and HTTP redirects, sensitive headers, body caps and
evidence handling. These are specific regression fixtures, not an exhaustive audit.
Mocked HTTP cases isolate exceptional paths; a loopback fixture checks actual
`requests` transport behavior without scanning a service. Read test names and any
reported skips alongside the overall result; a skipped integration is not a pass.

## Optional image smoke check

After building an image separately:

```sh
python verify_server.py --docker --image kali-security-mcp-server:latest
```

This starts the existing image with `--network none`, `--cap-drop ALL`,
`no-new-privileges`, an empty scope and a temporary bind mount. It does not start
DVWA, Metasploit, Active Directory, a crawler or a scanner. On POSIX hosts it runs
under the current user's UID/GID so the temporary workspace can be written.
Do not run it with `sudo`: that selects UID 0. This smoke config does not make the
container root filesystem read-only; network/capability restrictions are specific
checks, not a claim of complete container isolation.
Docker Desktop and remote-daemon mount behavior must be checked on those hosts.

## CI and explicit limits

The `checks` CI job installs the test dependencies and runs the offline regression
suite on every main-branch push or pull request, alongside syntax and Dockerfile
lint. An image build remains a separate workflow-dispatch job. The offline suite
is suitable for reviewing safety regressions without touching a live target.

A green suite is **not** evidence of:

- A successful complete Kali image build or availability of every binary.
- A successful lab assessment, valid findings on a real application, or end-to-end
  behavior of all 73 tool adapters.
- Complete secret detection/redaction, absence of vulnerabilities, or safe handling
  of every crawler-discovered URL or external-tool option.
- DNS pinning/rebinding protection or enforced isolation of external tools.
- Container smoke verification when only the local Python verifier was run.

For release review, record the exact commit, Python/dependency versions, the test
command and output, image digest/build result, and which explicitly owned lab
workflows were actually exercised. Keep synthetic fixtures separate from real
engagement evidence. A target scope configuration does not itself grant consent.
