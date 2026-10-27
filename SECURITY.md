# Security Policy

RED MCP is an **offensive-security toolkit**. It exposes Kali Linux security
tooling to an AI assistant over the Model Context Protocol for use in
**authorized penetration testing** engagements. The same capabilities that make
it useful for defenders make it dangerous when misused. Read this policy before
running any active tooling.

## Authorized Use Only

You may only use RED MCP against systems where you have **prior, explicit,
written authorization**. In practice this means one of:

- **You own the system** (or the account/organization that owns it), or
- **You hold a signed penetration-testing contract / rules-of-engagement**
  document that names the in-scope targets, or
- **You are testing under a bug-bounty program** that grants a
  **Safe Harbor** and the target is **explicitly in scope**.

Anything else is unauthorized access and is a **crime**. Relevant statutes
include the **US Computer Fraud and Abuse Act (CFAA)**, the
**UK Computer Misuse Act 1990**, and equivalent EU / national laws (e.g. the
EU Directive 2013/40/EU on attacks against information systems, Germany's
StGB §202, and comparable provisions elsewhere). Scanning, brute-forcing, or
exploiting a host you are not authorized to touch can expose you to criminal
prosecution and civil liability. **When in doubt, stop and get written
permission first.**

## Built-in Safeguards and Their Limits

- **Explicit scope:** scoped adapters reject empty or nonmatching allowlists. Hostname
  rules include subdomains with a label boundary; IP rules use CIDR membership.
  Tool targets must be individual hosts/IPs or URLs, not ranges. CIDRs configure
  scope. Deny rules take precedence for checked names/addresses. When an allowed
  name must be checked against denied IP ranges, failed DNS resolution blocks it.
- **HTTP redirect boundary:** the built-in HTTP transport validates the initial URL
  and every hop, blocks HTTPS downgrades, and strips caller headers on origin changes
  (scheme, host or port). Cross-origin redirects with bodies are blocked. Configured
  nonsensitive attribution may continue. Ambient proxy/.netrc authentication and
  automatic cookie-jar replay are disabled; credentials must be supplied explicitly.
  TLS verification defaults on; opting out is only appropriate for an explicitly
  owned self-signed lab. HTTP timeout/deadline checks are not a hard wall-clock
  interrupt for DNS or a blocked read; use external egress/process limits as well.
- **Bounded command capture:** the POSIX/Kali `_run` adapter captures stdout/stderr
  together while running. It terminates the process group on timeout/output overflow,
  reports exit status, and returns/saves a bounded preview. `MAX_OUTPUT_BYTES`
  defaults to 80,000 and `MAX_OUTPUT_CHARS` to 20,000. Caps apply to this adapter,
  not all SDK/RPC calls or files written directly by third-party tools.
- **Honest HTTP results:** a failed read, cap, deadline or blocked redirect is marked
  incomplete. Source-analysis consumers reject partial input; auth comparison
  reports become inconclusive rather than silently treating failures as equal.
- **Safer defaults:** the checked-in MCP config starts with no authorized target,
  all extra container capabilities dropped, and a portable named workspace volume.
  DVWA is published on loopback only. Configure the smallest explicit engagement
  scope yourself. Raw-socket features require a separate reviewed capability choice.
- **Constrained options:** sqlmap accepts only conservative, allowlisted knobs
  (level/risk 1, bounded timeout/retry/threads); target/file/OS options are rejected.
  Metasploit module strings cannot inject console commands, and run options are
  limited to RPORT/SSL/STOP_ON_SUCCESS rather than allowing target overrides.

### Evidence and credential handling

Built-in `http_request` stores private mode-0600 **metadata-only evidence by
default**. It fully masks recognized credential headers and known header credential
values in returned previews and evidence. Query strings/fragments are omitted from
recorded URLs. Bodies still appear as capped tool output, so the model/client can
see response data. Set `HTTP_SAVE_BODY_EVIDENCE=1` only when the engagement explicitly
requires persisted bodies: text masks known credentials; binary bytes remain raw.
Unknown secrets, personal data, URL paths, arbitrary headers and user-entered finding
text are **not guaranteed redacted**. Review before sharing. Other evidence helpers,
external tools, reports and files can still contain sensitive material.

Command logs/returned output/evidence mask recognized credential argument values,
including common password/header flags and embedded Impacket credentials. This is
not a universal secret detector. Command-created files and SDK/RPC output are not
covered by that masking policy. HTTP evidence never falls back to a shared `/tmp`
directory; workspace failures are visible. Use a private workspace, restrict host
and backup access, and apply an engagement-specific retention/deletion policy.
The application does not enforce expiry or encryption at rest.

### Remaining trust boundaries

Scope validation is **not an egress firewall** and does not pin DNS between checks
and connections. External scanners/crawlers, redirects within third-party tools,
name aliases, DNS changes, passive/OOB services, RPC operations and direct file
writes need separate review. Do not treat the allowlist or a passed regression suite
as proof every outbound request remains in scope. Isolate the container and enforce
network-level engagement boundaries. Run only trusted code with a private workspace;
path checks are not a sandbox against another process racing filesystem symlinks.

The stdio server assumes a trusted local MCP client. It is not a multi-tenant hosted
service and must not be exposed as an unauthenticated network service. Some legacy
operations are invasive; explicit confirmation on selected tools does not authorize
other actions. Tests use synthetic processes, mocked transports, loopback-only HTTP,
and real offline MCP sessions—not third-party targets or live security scans.
See [testing and coverage](docs/TESTING.md). No "perfect", "SSRF-safe", or production
readiness guarantee is made.

These safeguards reduce risk; they **do not grant authorization**.

## Reporting a Vulnerability in This Toolkit

If you discover a security issue in **RED MCP itself** (for example an
allowlist bypass, a scope-enforcement gap, a command-injection vector, or a
container-escape), please report it **privately** — do not open a public issue
and do not disclose it before a fix is available.

- Preferred: open a **private security advisory** on the project's repository
  (GitHub → *Security* → *Report a vulnerability*).
- Alternatively: email the maintainer (**raj7**) with a clear description,
  affected version/commit, and reproduction steps.

Please give a reasonable window for a fix before any public disclosure. We aim
to acknowledge reports promptly and will credit reporters who wish to be named.

## Disclaimer

RED MCP is provided **"as is", without warranty of any kind**, express or
implied. The authors and contributors accept **no liability** for any damage,
data loss, service disruption, or legal consequence arising from its use or
misuse. **You, the user, bear sole and full responsibility** for ensuring that
every action you take with this software is lawful and properly authorized.
