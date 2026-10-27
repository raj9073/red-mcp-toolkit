# RED MCP — Kali Security Toolkit for Claude (Authorized Pentesting)

Give Claude — via the Model Context Protocol — a **full-spectrum pentest toolkit**
running in an isolated Docker container, plus an "analyst layer" (persistent
workspace, structured output, web screenshots Claude can *see*, and auto-reporting).
Inspired by NetworkChuck's "I turned Claude into a hacker" demo. This is an
AI-assisted integration project with explicit testing and safety limitations.

> ## ⚠️ AUTHORIZED USE ONLY
> This connects an AI assistant to offensive security tooling, including
> exploitation and credential-attack tools. Only test systems you **own** or are
> **contractually authorized** to assess. Unauthorized access is illegal (US CFAA,
> UK Computer Misuse Act, etc.). Scoped entry points fail closed when their target
> is outside `KALI_TARGET_ALLOWLIST`. External-tool traffic still needs independent
> network controls; see [SECURITY.md](../SECURITY.md).

## How it works

```
Claude Code ──(MCP / stdio)──► docker run --rm -i  (ephemeral Kali container)
                                 ├─ 73 tools wrapped as @mcp.tool()s
                                 └─ /workspace volume (persists evidence, loot,
                                    screenshots, findings & the report)
```

The MCP client starts one container/server session. Tool calls share that session;
the container is removed when the session exits (`--rm`). The image uses a non-root
user. The checked-in config drops extra capabilities; raw-socket features need a
separately reviewed capability choice. The bounded command runner saves its redacted
preview under `/workspace/output/`, subject to workspace availability.

## Layout

```
RED MCP/
├─ .mcp.json                  # Claude Code MCP config (+ workspace mount)
├─ kali-mcp/
│  ├─ Dockerfile              # multi-stage: Go builder + Kali toolkit image
│  ├─ requirements.txt
│  ├─ kali_security_server.py # FastMCP server (73 tools)
│  └─ README.md               # this file
├─ lab/
│  └─ docker-compose.yml      # DVWA practice target on the redlab network
├─ workspace/                 # persistent: output/, screenshots/, findings, report.md
└─ verify_server.py           # end-to-end test client
```

## Prerequisites
- **Docker Desktop** (running) · **Claude Code**

## Setup

1. **Build the image** (large; multi-GB):
   ```powershell
   docker build -t kali-security-mcp-server:latest .\kali-mcp
   ```
2. **(Recommended) DVWA practice lab**:
   ```powershell
   docker compose -f .\lab\docker-compose.yml up -d
   ```
   DVWA → `http://localhost:8080` (browser) / `http://dvwa` (from the scanner).
   Log in `admin`/`password`, click **Create / Reset Database**.
3. **(Optional) Metasploit RPC service** — needed for the `msf_*` tools:
   ```powershell
   docker compose -f .\lab\msf-compose.yml up -d
   ```
4. **Set your scope** — edit `KALI_TARGET_ALLOWLIST` in `.mcp.json` (CIDRs/hosts).
5. **Load in Claude Code** — restart in this folder, approve `kali-security`,
   verify with `claude mcp list`.

## The analyst layer (what makes it powerful)
- **Persistent `/workspace`** — a Docker named volume in the default config.
  The bounded command adapter saves redacted previews to `output/`; external tools
  may create additional sensitive files. Inspect via `workspace_info`.
- **Structured output** — `nmap_scan` returns a parsed open-ports summary on top of
  the raw output, so Claude can plan precisely.
- **Visual triage** — `screenshot_web` uses gowitness+chromium to save PNGs to
  `workspace/screenshots/`, which Claude can open and *look at*.
- **Reporting** — `save_finding(...)` accumulates findings; `generate_report()`
  compiles `workspace/report.md`.

## Usage (just talk to Claude)
- *"Recon dvwa: nmap, httpx, whatweb, then crawl it with katana"*
- *"Gobuster + ffuf dvwa, screenshot it, and show me the screenshot"*
- *"Run nuclei and nikto on dvwa, save findings, then generate the report"*
- *"AD: kerbrute users on dc 10.0.0.10 (corp.local), then AS-REP roast"* *(needs an AD lab)*
- *"Kerberoast with svc:Pass1 on 10.0.0.10, then crack the hashes with john"*
- *"Enumerate SMB/SNMP on 10.0.0.5; BloodHound collect with creds"*
- *"hashid this hash, then john it"* · *"searchsploit vsftpd 2.3.4"*
- *"Search Metasploit for an SMB aux module and run it on 10.0.0.5"* (gated — I'll confirm RUN)

## Tools (73)

"Scoped" tools refuse any target not in `KALI_TARGET_ALLOWLIST` (—) = not scoped.

| Category | Tool | Scoped |
|---|---|:--:|
| Recon | `whois_lookup` · `dns_lookup` | — |
| Recon | `dns_enum` · `subdomain_enum` · `subfinder_enum` · `theharvester_scan` | ✅ |
| Discovery | `nmap_scan` (quick/default/full/vuln/discovery, structured) · `masscan_scan` | ✅ |
| Web content | `gobuster_dir` · `ffuf_fuzz` · `feroxbuster_scan` · `dirb_scan` · `katana_crawl` | ✅ |
| Web vuln | `nikto_scan` · `whatweb_scan` · `httpx_probe` · `wafw00f_scan` · `nuclei_scan` · `wpscan_scan` · `sqlmap_scan` · `dalfox_scan` · `arjun_scan` · `commix_scan` | ✅ |
| TLS | `sslscan_scan` · `testssl_scan` | ✅ |
| SMB / WinRM | `enum4linux_scan` · `smbmap_scan` · `smb_list_shares` · `netexec_smb` · `nbtscan_scan` · `winrm_exec` | ✅ |
| SNMP | `snmp_enum` · `snmp_bruteforce_community` | ✅ |
| Active Directory | `kerbrute_userenum` · `asrep_roast` · `kerberoast` · `secretsdump` · `ldap_search` · `bloodhound_collect` · `certipy_find` | ✅ |
| Auth / cracking | `hydra_bruteforce` · `john_crack` · `hashid_identify` | ✅ / — |
| Wordlists | `cewl_wordlist` · `crunch_wordlist` | ✅ / — |
| Screenshots | `screenshot_web` · `screenshot_hosts` (multi-host list) | ✅ |
| Exploitation | `msf_search` · `msf_module_info` · `msf_run` (gated: `confirm="RUN"`, audited) | ✅ |
| Cloud / IaC | `trivy_scan` (image/fs/repo/config — vulns + misconfig + secrets) | — |
| Reporting | `save_finding` · `list_findings` · `generate_report` · `workspace_info` | — |
| Exploit / util | `searchsploit_lookup` · `list_wordlists` · `authorized_scope` | — |
| **Auth / API** _(T1)_ | `http_request` · `jwt_decode` · `jwt_forge` · `idor_probe` · `api_ingest` | ✅ / — |
| **Attack surface** _(T2)_ | `js_analyze` · `secret_scan` · `wayback_urls` · `uncover_search` | ✅ / — |
| **Out-of-band** _(T3)_ | `oob_start` · `oob_poll` · `oob_stop` (interactsh — blind SSRF/XSS/SQLi/RCE) | — |
| **Orchestration** _(T4)_ | `recon_sweep` (subfinder→httpx→nuclei→screenshots) | ✅ |
| **Reporting** _(T5)_ | `cvss_score` · `generate_h1_report` (HackerOne-format) | — |

**Wordlist aliases** — web `common`/`small`/`medium`/`raft`/`dirb`; users
`default`/`names`; passwords `default`/`top100`/`rockyou`. `list_wordlists()` shows paths.

## Authenticated API & auth-logic testing (the T1–T6 upgrade)

These helpers support explicitly authorized API and authentication analysis.
Their output is evidence for manual review, not proof of a confirmed vulnerability:

- **`http_request`** — scope-checked, attributed, evidence-logged HTTP client. The header(s)
  from `ENGAGEMENT_ATTRIBUTION` are injected subject to redirect credential policy.
  It produces private metadata-only evidence by default; body retention is opt-in.
  TLS certificate verification defaults on; `verify_tls=False` is an explicit owned-lab opt-out.
  Known header credentials are masked, but previews and unknown secrets need review.
- **`jwt_decode` / `jwt_forge`** — inspect claims; craft tokens for authorized testing
  (`sign` / `none` / RS→HS `confuse` algorithm-confusion).
- **`idor_probe`** — cross-account BOLA/IDOR harness: fetches the same object as owner vs.
  another account vs. unauthenticated access and marks responses for manual review.
  Partial or failed requests are inconclusive; matching status alone does not prove BOLA.
- **`api_ingest`** — turn a Swagger/OpenAPI/Postman file into a flat endpoint inventory.
- **`js_analyze` / `secret_scan`** — pull endpoints + leaked secrets out of JS bundles/files.
- **`oob_start` / `oob_poll`** — interactsh listener for **blind** SSRF/XSS/SQLi/RCE callbacks.
- **`recon_sweep`** — one call: subfinder → httpx → nuclei → screenshots, deduped/parallelized.
- **`cvss_score` / `generate_h1_report`** — CVSS v3.1 scoring + a HackerOne-ready report.

**New env vars** (set in `.mcp.json`):

| Var | Purpose |
|---|---|
| `ENGAGEMENT_ATTRIBUTION` | Header(s) auto-injected by the HTTP tools, `"K: V; K2: V2"` — e.g. `X-HackerOne-Research: raj7; User-Agent: raj7` |
| `KALI_TARGET_DENYLIST` | CIDRs/hosts that are **always** out of scope (deny wins over the allowlist — e.g. production) |
| `HTTP_TIMEOUT` | Per-request timeout (default 30s) |
| `HTTP_MIN_INTERVAL` | Min seconds between requests per host (politeness / rate-limit; default 0) |

*"ingest sign_swagger.json, forge a token for tenant B, then idor_probe the document endpoint with tenant-A and tenant-B tokens"*.

## Safety controls
- **Scoped entry points**, optional deny rules, non-root image defaults, constrained
  command options, bounded POSIX command capture and optional built-in HTTP pacing.
  Some legacy helpers and external tools use different execution/network paths;
  these controls are not a universal sandbox. See [SECURITY.md](../SECURITY.md).
- **Evidence trail** — every command + output auto-saved to `workspace/output/`; HTTP
  metadata saved privately under `workspace/evidence/` by default. Bodies require
  `HTTP_SAVE_BODY_EVIDENCE=1` and may contain sensitive data.
- **Attribution** — configured headers are injected by the built-in HTTP transport;
  credential-like attribution is removed on cross-origin redirects.
- **Known credential values masked** in the bounded command adapter and built-in
  HTTP previews/evidence; not a universal secret detector. See the security policy.

## Troubleshooting
- **MCP server won't start** → Docker running? (`docker info`)  ·  `network redlab not found` → bring up the lab or `docker network create redlab`.
- **Everything "blocked"** → target not in `KALI_TARGET_ALLOWLIST` (`authorized_scope`).
- **Workspace not writable** → `workspace_info` shows `writable=False`; check the `-v` mount path in `.mcp.json`.
- **Screenshots empty** → gowitness needs the bundled chromium (`CHROME_PATH=/usr/bin/chromium`); confirm the target serves HTTP.
- **AD tools** → most need valid domain creds and a reachable DC; full testing needs an AD lab (DVWA is not AD).

## Hardened development workflow and compatibility notes

Start with [the offline verification workflow](../docs/TESTING.md). It exercises real
MCP protocol startup and reporting without any scanner or live engagement target.
Read [SECURITY.md](../SECURITY.md) before enabling scope; the allowlist is not a
network sandbox and unknown secrets are not automatically safe to share.

The checked-in `.mcp.json` uses the portable Docker named volume
`red-mcp-workspace` instead of a developer-specific host path, and starts with an
empty allowlist and dropped capabilities. Add only your authorized individual host
names or CIDRs to the scope configuration. Tool target parameters accept individual
hosts/IPs/URLs, not CIDR sweeps. To inspect/export volume data, use your Docker volume
workflow; alternatively configure a private absolute host bind path with permissions
for the image's UID 1000. Do not add broad private-network ranges by default.

SQLmap `extra` is now restricted to `--batch`, `--level=1`, `--risk=1`,
`--timeout=1..60`, `--retries=0..2`, and `--threads=1..4`. Unsupported options fail
before execution. Metasploit run options allow only `RPORT`, `SSL` and
`STOP_ON_SUCCESS`; free-form console/payload/target overrides are intentionally blocked.
HTTP transport ignores ambient proxies and `.netrc`, checks redirects by origin,
blocks HTTPS downgrades and cross-origin bodies, and marks partial reads incomplete.
`MAX_OUTPUT_BYTES` controls live command capture, not only display truncation;
stdout/stderr are merged and an exit status/termination marker is returned.
