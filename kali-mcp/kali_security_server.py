#!/usr/bin/env python3
"""
RED MCP - Kali Security Tools MCP server (FastMCP, stdio transport).

Full-spectrum pentest toolkit + an "analyst layer": a persistent /workspace,
structured nmap output, web screenshots Claude can view, and findings/report
helpers.

============================  AUTHORIZED USE ONLY  ============================
Scoped tool entry points validate targets against KALI_TARGET_ALLOWLIST.
This is not a network sandbox: external tools may discover additional targets.
Only test systems you own or are contractually authorized to assess. Unauthorized access is illegal.
==============================================================================

Env:
  KALI_TARGET_ALLOWLIST  CIDRs/hostnames in scope (empty => active tools blocked)
  KALI_TARGET_DENYLIST   CIDRs/hostnames ALWAYS out of scope (deny wins; e.g. prod)
  ENGAGEMENT_ATTRIBUTION HTTP header(s) auto-injected by the http tools, "K: V; K2: V2"
                         (e.g. a program-required "X-HackerOne-Research: <handle>")
  SCAN_TIMEOUT           default per-command timeout, seconds (default 300)
  HTTP_TIMEOUT           per-HTTP-request timeout, seconds (default 30)
  HTTP_MIN_INTERVAL      min seconds between requests per host (politeness; default 0)
  MAX_OUTPUT_CHARS       command-output preview limit (default 20000)
  MAX_OUTPUT_BYTES       running command capture cap (default 4 * MAX_OUTPUT_CHARS)
  HTTP_SAVE_BODY_EVIDENCE opt in to sensitive HTTP body retention (default 0)
  WORKSPACE              persistent dir for evidence/reports (default /workspace)
"""
import os
import re
import sys
import json
import time
import shlex
import socket
import logging
import datetime
import ipaddress
import subprocess
import base64
import threading
import selectors
import signal
import tempfile
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, urljoin

from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                    format="%(asctime)s [kali-mcp] %(levelname)s %(message)s")
log = logging.getLogger("kali-mcp")
mcp = FastMCP("kali-security")

SCAN_TIMEOUT = int(os.environ.get("SCAN_TIMEOUT", "300"))
MAX_OUTPUT_CHARS = int(os.environ.get("MAX_OUTPUT_CHARS", "20000"))
MAX_OUTPUT_BYTES = int(os.environ.get("MAX_OUTPUT_BYTES", str(4 * MAX_OUTPUT_CHARS)))
ALLOWLIST_RAW = os.environ.get("KALI_TARGET_ALLOWLIST", "").strip()
WORKSPACE = os.environ.get("WORKSPACE", "/workspace")

# --- Tier-6 hardening knobs -------------------------------------------------
DENYLIST_RAW = os.environ.get("KALI_TARGET_DENYLIST", "").strip()
ATTRIBUTION_RAW = os.environ.get("ENGAGEMENT_ATTRIBUTION", "").strip()
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "30"))
HTTP_MIN_INTERVAL = float(os.environ.get("HTTP_MIN_INTERVAL", "0"))  # per-host politeness delay (s)
MAX_BODY_CHARS = int(os.environ.get("MAX_BODY_CHARS", str(MAX_OUTPUT_CHARS)))
MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", str(5 * 1024 * 1024)))  # cap streamed body read

_SAFE = re.compile(r"^[A-Za-z0-9._:,\-/?=&%~+@]+$")  # comma allowed (ports/severity/match-codes lists)

WEB_WORDLISTS = {
    "common": "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "small": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "medium": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "raft": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "dirb": "/usr/share/dirb/wordlists/common.txt",
}
USER_WORDLISTS = {
    "default": "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    "names": "/usr/share/seclists/Usernames/Names/names.txt",
}
PASS_WORDLISTS = {
    "default": "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
    "top100": "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt",
    "rockyou": "/usr/share/wordlists/rockyou.txt",
}
_web_wl = lambda n: WEB_WORDLISTS.get(n, WEB_WORDLISTS["common"])
_user_wl = lambda n: USER_WORDLISTS.get(n, USER_WORDLISTS["default"])
_pass_wl = lambda n: PASS_WORDLISTS.get(n, PASS_WORDLISTS["default"])


# --- allowlist / validation -------------------------------------------------
def _parse_allowlist(raw):
    nets, hosts = [], []
    for item in (x.strip().lower().rstrip(".") for x in raw.split(",") if x.strip()):
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            host = item.lstrip(".")
            if len(host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                      for label in host.split(".")):
                raise ValueError("Scope entries must be valid IP/CIDR or ASCII hostnames") from None
            hosts.append(host)
    return nets, hosts


ALLOW_NETS, ALLOW_HOSTS = _parse_allowlist(ALLOWLIST_RAW)
DENY_NETS, DENY_HOSTS = _parse_allowlist(DENYLIST_RAW)


def _parse_headers_spec(raw: str) -> dict:
    """Parse a 'K: V; K2: V2' (or newline-separated) string into a header dict."""
    out = {}
    for part in re.split(r"[;\n]+", raw or ""):
        part = part.strip()
        if not part or ":" not in part:
            continue
        k, v = part.split(":", 1)
        if k.strip():
            out[k.strip()] = v.strip()
    return out


ATTRIBUTION = _parse_headers_spec(ATTRIBUTION_RAW)


def _extract_host(target: str) -> str:
    """Extract a single normalized host, never an option or a list of targets."""
    t = target.strip()
    try:
        if "://" in t:
            parsed = urlparse(t)
            if parsed.username is not None or parsed.password is not None:
                return ""
            t = parsed.hostname or ""
        else:
            t = t.split("/")[0].split("?")[0]
            if t.startswith("["):
                t = urlparse("//" + t).hostname or ""
            elif t.count(":") == 1:
                host, port = t.rsplit(":", 1)
                if not port.isdigit() or not 1 <= int(port) <= 65535:
                    return ""
                t = host
        t = t.lower().rstrip(".")
        if not t or t.startswith("-") or any(c in t for c in ",@%"):
            return ""
        try:
            return str(ipaddress.ip_address(t))
        except ValueError:
            labels = t.split(".")
            if len(t) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x)
                                   for x in labels):
                return ""
            return t
    except (ValueError, TypeError):
        return ""


def _in_scope(target: str):
    if not ALLOW_NETS and not ALLOW_HOSTS:
        return False, ("No KALI_TARGET_ALLOWLIST configured - refusing (fail-closed). "
                       "Set it to your authorized engagement scope.")
    # Tool adapters expect one host. Do not silently turn a range into its first IP.
    if "://" not in target and "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
        except ValueError:
            pass
        else:
            return False, "Use an individual host/IP target; CIDRs belong in the scope configuration."
    host = _extract_host(target)
    if not host:
        return False, "Could not parse a single valid host from the target."
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if any(ip in net for net in DENY_NETS):
            return False, "Target is explicitly out of scope (KALI_TARGET_DENYLIST)."
        if any(ip in net for net in ALLOW_NETS):
            return True, host
    else:
        if any(host == h or host.endswith("." + h) for h in DENY_HOSTS):
            return False, "Target is explicitly out of scope (KALI_TARGET_DENYLIST)."
        # Only resolve already-allowed names. An unresolved deny check must not pass.
        if any(host == h or host.endswith("." + h) for h in ALLOW_HOSTS):
            if DENY_NETS:
                ips = _resolve_ips(host)
                if not ips:
                    return False, "Cannot verify address denylist: DNS resolution failed."
                if any(ip in net for ip in ips for net in DENY_NETS):
                    return False, "Target resolves to an explicitly denied address."
            return True, host
    return False, "Target is not within the authorized allowlist."


def _sanitize(value: str) -> str:
    value = value.strip()
    if not value or value.startswith("-") or not _SAFE.fullmatch(value):
        raise ValueError("Refusing malformed/unsafe argument.")
    return value


_SEARCH_RE = re.compile(r"^[A-Za-z0-9 _\-:./]+$")  # allows spaces/colons; no newlines/;/shell meta


def _searchq(value: str) -> str:
    value = value.strip()
    if not value or not _SEARCH_RE.match(value):
        raise ValueError(f"invalid search query: {value!r}")
    return value


def _arg(value: str) -> str:
    value = value.strip()
    if value.startswith("-") or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("argument may not start with '-' or contain control characters")
    return value


def _guard(target: str):
    try:
        target = _sanitize(target)
    except ValueError as e:
        return None, None, f"[blocked] {e}"
    ok, detail = _in_scope(target)
    if not ok:
        log.warning("BLOCKED target: %s", detail)
        return None, None, f"[blocked] {detail}"
    return target, (_extract_host(target) or target), None


def _url(target: str, host: str) -> str:
    return target if "://" in target else f"http://{host}"


def _resolve(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return host


def _resolve_ips(host: str):
    """Best-effort: all IPs a hostname resolves to (for denylist enforcement across name/IP forms)."""
    ips = []
    try:
        for _fam, _s, _p, _c, sa in socket.getaddrinfo(host, None):
            try:
                ips.append(ipaddress.ip_address(sa[0]))
            except ValueError:
                pass
    except Exception:  # noqa: BLE001
        pass
    return ips


def _pd_target(target: str, host: str):
    """ProjectDiscovery tools (httpx/katana/nuclei) use their own public DNS resolvers,
    so resolve via the system resolver and pass the IP + a Host header to keep vhosts working."""
    ip = _resolve(host)
    scheme = "https" if str(target).startswith("https") else "http"
    extra = ["-H", f"Host: {host}"] if ip != host else []
    return f"{scheme}://{ip}", extra


# --- workspace --------------------------------------------------------------
def _ws_dir(sub: str = ""):
    root = os.path.realpath(WORKSPACE)
    d = os.path.realpath(os.path.join(root, sub))
    if os.path.commonpath([root, d]) != root:
        return None
    try:
        os.makedirs(d, mode=0o700, exist_ok=True)
        return d
    except Exception:
        return None


def _ws_available() -> bool:
    d = _ws_dir()
    if not d:
        return False
    try:
        fd, path = tempfile.mkstemp(prefix=".write-test-", dir=d)
        os.close(fd)
        os.remove(path)
        return True
    except Exception:
        return False


def _ts():
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")


def _ws_path(source: str) -> str:
    """Resolve a user-supplied path and confine it to WORKSPACE (fail-closed against traversal)."""
    ws = os.path.realpath(WORKSPACE)
    p = os.path.realpath(source if os.path.isabs(source) else os.path.join(ws, source))
    if p != ws and not p.startswith(ws + os.sep):
        raise ValueError("path escapes the workspace")
    return p


# --- command runner ---------------------------------------------------------
_SECRET_FLAGS = {"--password", "--passwd", "--token", "--api-key",
                 "--secret", "--auth", "--cookie", "--cookies"}


def _command_secrets(cmd):
    """Known argument credentials only; arbitrary tool output still needs human review."""
    values = set()
    previous = ""
    secret_flags = set(_SECRET_FLAGS)
    executable = os.path.basename(str(cmd[0]))
    if executable in {"nxc", "netexec", "certipy-ad", "bloodhound-python", "hydra", "medusa", "evil-winrm"}:
        secret_flags.add("-p")
    if executable == "ldapsearch" or (executable == "env" and "ldapsearch" in cmd[:4]):
        secret_flags.add("-w")
    if executable == "snmpwalk":
        secret_flags.add("-c")
    for index, item in enumerate(cmd):
        value = str(item)
        key, sep, inline = value.partition("=")
        if previous in secret_flags and value:
            values.add(value)
        if sep and key.lower() in secret_flags and inline:
            values.add(inline)
        if previous in {"-H", "--header"} and ":" in value:
            name, credential = value.split(":", 1)
            if name.strip().lower() in {"authorization", "proxy-authorization", "cookie",
                                        "x-api-key", "api-key", "x-auth-token"}:
                if credential.strip():
                    values.add(credential.strip())
                    if credential.strip().lower().startswith(("bearer ", "basic ")):
                        values.add(credential.strip().split(None, 1)[1])
        # Impacket's domain/user:password[@host] format.
        if index == 1 and executable.startswith("impacket-") and ":" in value:
            credential = value.split(":", 1)[1]
            if executable == "impacket-secretsdump":
                credential = credential.rsplit("@", 1)[0]
            if credential:
                values.add(credential)
        if "://" in value:
            try:
                parsed = urlparse(value)
                if parsed.password:
                    values.add(parsed.password)
                from urllib.parse import unquote_plus
                for pair in parsed.query.split("&"):
                    name, sep, credential = pair.partition("=")
                    if sep and re.search(r"(?i)(password|passwd|secret|token|api.?key|authorization)", unquote_plus(name)) and credential:
                        values.update((credential, unquote_plus(credential)))
            except ValueError:
                pass
        previous = value
    return sorted(values, key=len, reverse=True)


def _mask_command_secrets(text, secrets):
    for secret in secrets:
        text = text.replace(secret, "***")
    return text


def _mask_command_bytes(data, secrets):
    """Mask credentials before decoding, including a cap inside a UTF-8 codepoint."""
    for secret in secrets:
        pattern = secret.encode("utf-8")
        data = data.replace(pattern, b"***")
        # KMP prefix table: linear-time suffix/prefix match, even for long credentials.
        prefix = [0] * len(pattern)
        matched = 0
        for i in range(1, len(pattern)):
            while matched and pattern[i] != pattern[matched]:
                matched = prefix[matched - 1]
            if pattern[i] == pattern[matched]:
                matched += 1
            prefix[i] = matched
        matched = 0
        for byte in data[-len(pattern):]:
            while matched and (matched == len(pattern) or byte != pattern[matched]):
                matched = prefix[matched - 1]
            if byte == pattern[matched]:
                matched += 1
        if matched:
            data = data[:-matched] + b"***"
    return data


def _redact(cmd):
    secrets = _command_secrets(cmd)
    # Mask before quoting: embedded quotes must not split a credential into visible pieces.
    return shlex.join([_mask_command_secrets(str(c), secrets) for c in cmd])


def _stop_process_group(proc):
    """Kali/POSIX: terminate descendants as well as the immediate wrapper."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    finally:
        proc.wait(timeout=5)


def _run(cmd, timeout=None, input_text=None, cwd=None) -> str:
    """Bound capture *while running*, kill the process group on deadline/overflow.

    stdout/stderr are intentionally merged to preserve order and avoid pipe deadlock.
    Commands are argv-only; stdin is bounded. This runner targets the POSIX Kali image.
    """
    timeout = SCAN_TIMEOUT if timeout is None else timeout
    if not cmd or not isinstance(timeout, (int, float)) or not 0 < timeout <= 86400:
        return "[error] invalid command or timeout"
    if not 1 <= MAX_OUTPUT_BYTES <= 16 * 1024 * 1024 or not 1 <= MAX_OUTPUT_CHARS <= 4 * 1024 * 1024:
        return "[error] output limits must be positive and bounded"
    if os.name != "posix":
        return "[error] external commands require the POSIX Kali container"
    if input_text is not None and len(input_text) > 1024 * 1024:
        return "[error] stdin exceeds 1 MiB character limit"
    payload = input_text.encode("utf-8") if input_text is not None else None
    secrets = _command_secrets(cmd)
    display_cmd = _redact(cmd)
    log.info("exec: %s", display_cmd)
    proc = None
    captured = bytearray()
    status = ""
    try:
        with selectors.DefaultSelector() as selector:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    stdin=subprocess.PIPE if payload is not None else subprocess.DEVNULL,
                                    cwd=cwd, start_new_session=True)
            os.set_blocking(proc.stdout.fileno(), False)
            selector.register(proc.stdout, selectors.EVENT_READ, "out")
            offset = 0
            if payload:
                os.set_blocking(proc.stdin.fileno(), False)
                selector.register(proc.stdin, selectors.EVENT_WRITE, "in")
            elif proc.stdin is not None:
                proc.stdin.close()
            deadline = time.monotonic() + timeout
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    status = f"[timed out after {timeout}s; process group terminated]"
                    _stop_process_group(proc)
                    break
                for key, _events in selector.select(min(remaining, 0.1)):
                    if key.data == "in":
                        try:
                            offset += os.write(key.fd, payload[offset:offset + 65536])
                        except BrokenPipeError:
                            offset = len(payload)
                        if offset == len(payload):
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                    else:
                        chunk = os.read(key.fd, min(65536, MAX_OUTPUT_BYTES - len(captured) + 1))
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        room = MAX_OUTPUT_BYTES - len(captured)
                        captured.extend(chunk[:room])
                        if len(chunk) > room:
                            status = f"[output limit reached at {MAX_OUTPUT_BYTES} bytes; process group terminated]"
                            _stop_process_group(proc)
                            break
                if status:
                    break
            if not status:
                try:
                    proc.wait(timeout=max(0.001, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    status = f"[timed out after {timeout}s; process group terminated]"
                    _stop_process_group(proc)
            if not status:
                status = f"[exit code: {proc.returncode}]"
    except FileNotFoundError:
        return f"[error] tool not found in container: {os.path.basename(str(cmd[0]))}"
    except Exception as exc:  # noqa: BLE001
        status = f"[error] command failed: {type(exc).__name__}"
    finally:
        if proc is not None:
            # Even a successful parent can leave descendants with closed pipes.
            try:
                _stop_process_group(proc)
            except (OSError, subprocess.TimeoutExpired):
                pass
            for stream in (proc.stdout, proc.stdin):
                if stream is not None:
                    stream.close()
    out = _mask_command_bytes(bytes(captured), secrets).decode("utf-8", "replace").strip() or "(no output)"
    if len(out) > MAX_OUTPUT_CHARS:
        out = out[:MAX_OUTPUT_CHARS] + f"\n... [truncated at {MAX_OUTPUT_CHARS} chars]"
    out += "\n" + status
    # Evidence is the same bounded/redacted view returned to the caller, not raw output.
    try:
        d = _ws_dir("output")
        if not d:
            raise OSError("workspace output unavailable")
        if d:
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(str(cmd[0])))
            fd, path = tempfile.mkstemp(prefix=safe + "-", suffix=".txt", dir=d)
            with os.fdopen(fd, "w", encoding="utf-8", errors="replace") as fh:
                fh.write("$ " + display_cmd + "\n\n" + out)
    except OSError:
        out += "\n[warning] evidence could not be saved"
    return out


def _scope_str() -> str:
    if not ALLOW_NETS and not ALLOW_HOSTS:
        return "No scope configured (all active tools blocked)."
    nets = ", ".join(str(n) for n in ALLOW_NETS) or "(none)"
    hosts = ", ".join(ALLOW_HOSTS) or "(none)"
    s = f"networks=[{nets}] hosts=[{hosts}] timeout={SCAN_TIMEOUT}s"
    if DENY_NETS or DENY_HOSTS:
        s += " deny=[" + ", ".join([str(n) for n in DENY_NETS] + list(DENY_HOSTS)) + "]"
    if ATTRIBUTION:
        s += " attribution=[" + ", ".join(ATTRIBUTION) + "]"
    return s


# ===========================================================================
#  RECON - passive (NOT scope-checked)
# ===========================================================================
@mcp.tool()
def whois_lookup(target: str) -> str:
    """WHOIS registry lookup for a domain or IP (passive; not scope-restricted)."""
    t = _sanitize(target)
    return _run(["whois", _extract_host(t) or t], timeout=60)


@mcp.tool()
def dns_lookup(target: str, record_type: str = "A") -> str:
    """DNS lookup via dig (passive). record_type: A,AAAA,MX,NS,TXT,CNAME,SOA,SRV,PTR,ANY."""
    t = _sanitize(target)
    rt = record_type.upper()
    if rt not in {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "PTR", "ANY"}:
        return "[error] invalid record_type"
    return _run(["dig", "+noall", "+answer", _extract_host(t) or t, rt], timeout=30)


# ===========================================================================
#  RECON - targeted OSINT (scope-checked)
# ===========================================================================
@mcp.tool()
def dns_enum(domain: str) -> str:
    """DNS enumeration (records, zone-transfer attempt) via dnsrecon."""
    _, host, err = _guard(domain)
    return err or _run(["dnsrecon", "-d", host])


@mcp.tool()
def subdomain_enum(domain: str) -> str:
    """Subdomain discovery from public sources via Sublist3r."""
    _, host, err = _guard(domain)
    return err or _run(["sublist3r", "-d", host])


@mcp.tool()
def subfinder_enum(domain: str) -> str:
    """Fast passive subdomain enumeration via subfinder."""
    _, host, err = _guard(domain)
    return err or _run(["subfinder", "-d", host, "-silent"], timeout=max(SCAN_TIMEOUT, 300))


@mcp.tool()
def theharvester_scan(domain: str, source: str = "bing") -> str:
    """OSINT emails/hosts/subdomains via theHarvester. source: bing, duckduckgo, crtsh, ..."""
    _, host, err = _guard(domain)
    return err or _run(["theHarvester", "-d", host, "-b", _arg(source), "-l", "100"])


# ===========================================================================
#  DISCOVERY - hosts & ports (scope-checked)
# ===========================================================================
NMAP_PROFILES = {
    "quick": ["-T4", "-F"],
    "default": ["-sV", "-T4", "--top-ports", "1000"],
    "full": ["-sV", "-T4", "-p-"],
    "vuln": ["-sV", "--script", "vuln", "-T4"],
    "discovery": ["-sn"],
}


def _nmap_summary(xml_path: str) -> str:
    try:
        root = ET.parse(xml_path).getroot()
    except Exception:
        return ""
    lines = []
    for host in root.findall("host"):
        addr = host.find("address")
        ip = addr.get("addr") if addr is not None else "?"
        hn = host.find("hostnames/hostname")
        name = ("/" + hn.get("name")) if hn is not None and hn.get("name") else ""
        ports = host.find("ports")
        if ports is None:
            continue
        for p in ports.findall("port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = p.find("service")
            sname = svc.get("name", "") if svc is not None else ""
            extra = " ".join(filter(None, [
                svc.get("product", "") if svc is not None else "",
                svc.get("version", "") if svc is not None else ""]))
            lines.append(f"{ip}{name} {p.get('portid')}/{p.get('protocol')} {sname} {extra}".rstrip())
    return "\n".join(lines)


@mcp.tool()
def nmap_scan(target: str, profile: str = "default", ports: str = "") -> str:
    """nmap scan (returns a structured open-port summary + full output).
    profile: quick|default|full|vuln|discovery. ports: explicit spec overriding the profile."""
    target, host, err = _guard(target)
    if err:
        return err
    flags = list(NMAP_PROFILES.get(profile, NMAP_PROFILES["default"]))
    if ports:
        ports = _sanitize(ports)
        flags = [f for f in flags if f not in ("--top-ports", "1000", "-F")]
        flags += ["-p", ports]
    xmlp = f"/tmp/nmap-{os.getpid()}-{_ts()}.xml"
    raw = _run(["nmap", *flags, "-oX", xmlp, host])
    summ = _nmap_summary(xmlp)
    try:
        os.remove(xmlp)
    except Exception:
        pass
    return (f"OPEN PORTS (ip[/name] port/proto service version):\n{summ}\n\n--- full output ---\n{raw}"
            if summ else raw)


@mcp.tool()
def masscan_scan(target: str, ports: str = "1-1000", rate: str = "1000") -> str:
    """Very fast port scan via masscan. ports e.g. '1-1000' or '80,443'; rate = packets/sec."""
    target, host, err = _guard(target)
    return err or _run(["masscan", host, "-p", _sanitize(ports), "--rate", _sanitize(rate), "--wait", "2"])


# ===========================================================================
#  WEB - content discovery & crawling (scope-checked)
# ===========================================================================
@mcp.tool()
def gobuster_dir(target: str, wordlist: str = "common", extensions: str = "") -> str:
    """Directory/file brute force via gobuster. wordlist: common|small|medium|raft|dirb."""
    target, host, err = _guard(target)
    if err:
        return err
    cmd = ["gobuster", "dir", "-u", _url(target, host), "-w", _web_wl(wordlist), "-q", "-t", "50", "--no-error"]
    if extensions:
        cmd += ["-x", _sanitize(extensions)]
    return _run(cmd)


@mcp.tool()
def ffuf_fuzz(url: str, wordlist: str = "common", match_codes: str = "200,204,301,302,307,401,403") -> str:
    """Fuzz a URL with ffuf (FUZZ keyword; /FUZZ appended if absent). wordlist: common|small|medium|raft|dirb."""
    target, host, err = _guard(url)
    if err:
        return err
    u = url if "FUZZ" in url else (url.rstrip("/") + "/FUZZ" if "://" in url else f"http://{host}/FUZZ")
    return _run(["ffuf", "-u", u, "-w", _web_wl(wordlist), "-mc", _sanitize(match_codes), "-s"])


@mcp.tool()
def feroxbuster_scan(target: str, wordlist: str = "common") -> str:
    """Recursive web content discovery via feroxbuster. wordlist: common|small|medium|raft|dirb."""
    target, host, err = _guard(target)
    return err or _run(["feroxbuster", "-u", _url(target, host), "-w", _web_wl(wordlist),
                        "-q", "--no-state", "-k", "--auto-bail"])


@mcp.tool()
def dirb_scan(target: str, wordlist: str = "common") -> str:
    """Directory brute force with dirb. wordlist: common|big|small."""
    target, host, err = _guard(target)
    if err:
        return err
    wl = {"common": "/usr/share/dirb/wordlists/common.txt",
          "big": "/usr/share/dirb/wordlists/big.txt",
          "small": "/usr/share/dirb/wordlists/small.txt"}.get(wordlist, "/usr/share/dirb/wordlists/common.txt")
    return _run(["dirb", _url(target, host), wl, "-S"])


@mcp.tool()
def katana_crawl(target: str, depth: int = 2) -> str:
    """Crawl a web app and list discovered URLs/endpoints via katana."""
    target, host, err = _guard(target)
    if err:
        return err
    url, extra = _pd_target(target, host)
    return _run(["katana", "-u", url, "-d", str(int(depth)), "-silent", "-nc", *extra],
                timeout=max(SCAN_TIMEOUT, 300))


# ===========================================================================
#  WEB - vuln scanning & fingerprinting (scope-checked)
# ===========================================================================
@mcp.tool()
def nikto_scan(target: str) -> str:
    """Nikto web-server vulnerability scan."""
    target, host, err = _guard(target)
    return err or _run(["nikto", "-host", _url(target, host), "-ask", "no"])


@mcp.tool()
def whatweb_scan(target: str) -> str:
    """Fingerprint web technologies with WhatWeb."""
    target, host, err = _guard(target)
    return err or _run(["whatweb", "-a", "3", _url(target, host)])


@mcp.tool()
def httpx_probe(target: str) -> str:
    """Probe an HTTP service for status/title/tech/server via httpx-toolkit."""
    target, host, err = _guard(target)
    if err:
        return err
    url, extra = _pd_target(target, host)
    return _run(["httpx-toolkit", "-title", "-tech-detect", "-status-code",
                 "-web-server", "-silent", "-nc", *extra],
                timeout=120, input_text=url + "\n")


@mcp.tool()
def wafw00f_scan(target: str) -> str:
    """Detect/fingerprint a Web Application Firewall with wafw00f."""
    target, host, err = _guard(target)
    return err or _run(["wafw00f", _url(target, host)])


@mcp.tool()
def nuclei_scan(target: str, severity: str = "medium,high,critical") -> str:
    """Template-based vulnerability scan with nuclei. severity: info,low,medium,high,critical (comma list)."""
    target, host, err = _guard(target)
    if err:
        return err
    url, extra = _pd_target(target, host)
    return _run(["nuclei", "-u", url, "-severity", _sanitize(severity),
                 "-silent", "-nc", *extra], timeout=max(SCAN_TIMEOUT, 600))


@mcp.tool()
def wpscan_scan(target: str) -> str:
    """Scan a WordPress site for vulns + enumerate plugins/users with WPScan."""
    target, host, err = _guard(target)
    return err or _run(["wpscan", "--url", _url(target, host), "--no-banner", "--no-update",
                        "--disable-tls-checks", "--enumerate", "vp,u"])


def _sqlmap_options(extra: str):
    """Compatibility parser: only conservative knobs, never target/file/OS options."""
    tokens = shlex.split(extra)
    parsed = {"--batch": None, "--level": "1", "--risk": "1"}
    limits = {"--level": (1, 1), "--risk": (1, 1), "--timeout": (1, 60),
              "--retries": (0, 2), "--threads": (1, 4)}
    i = 0
    while i < len(tokens):
        option, sep, value = tokens[i].partition("=")
        if option == "--batch" and not sep:
            i += 1
            continue
        if option not in limits:
            raise ValueError("unsupported sqlmap option; target/file/OS options are not permitted")
        if not sep:
            i += 1
            if i == len(tokens):
                raise ValueError("sqlmap option is missing its value")
            value = tokens[i]
        low, high = limits[option]
        if not value.isdigit() or not low <= int(value) <= high:
            raise ValueError(f"{option} must be between {low} and {high}")
        parsed[option] = str(int(value))
        i += 1
    out = []
    for option, value in parsed.items():
        out.append(option)
        if value is not None:
            out.append(value)
    return out


@mcp.tool()
def sqlmap_scan(target: str, extra: str = "--batch --level 1 --risk 1") -> str:
    """Authorized sqlmap check. Extra accepts only --batch, --level=1, --risk=1,
    --timeout=1..60, --retries=0..2 and --threads=1..4. Other options are blocked."""
    target, host, err = _guard(target)
    if err:
        return err
    if "://" not in target:
        return "[error] sqlmap needs a full URL with parameters, e.g. http://host/p.php?id=1"
    try:
        options = _sqlmap_options(extra)
    except ValueError as exc:
        return f"[blocked] {exc}"
    return _run(["sqlmap", "-u", target, *options])


@mcp.tool()
def dalfox_scan(target: str) -> str:
    """Scan a URL (ideally with a parameter) for XSS with dalfox."""
    target, host, err = _guard(target)
    if err:
        return err
    if "://" not in target:
        return "[error] dalfox needs a full URL, e.g. http://host/p.php?q=1"
    return _run(["dalfox", "url", target, "--no-color", "--silence"], timeout=max(SCAN_TIMEOUT, 600))


@mcp.tool()
def arjun_scan(target: str) -> str:
    """Discover hidden HTTP parameters with arjun."""
    target, host, err = _guard(target)
    return err or _run(["arjun", "-u", _url(target, host)], timeout=max(SCAN_TIMEOUT, 600))


@mcp.tool()
def commix_scan(target: str) -> str:
    """Test a URL (with a parameter) for command injection with commix (batch mode)."""
    target, host, err = _guard(target)
    if err:
        return err
    if "://" not in target:
        return "[error] commix needs a full URL with a parameter, e.g. http://host/p.php?x=1"
    return _run(["commix", "--url", target, "--batch", "--output-dir", "/tmp/commix"],
                timeout=max(SCAN_TIMEOUT, 600))


# ===========================================================================
#  TLS / SSL (scope-checked)
# ===========================================================================
@mcp.tool()
def sslscan_scan(target: str, port: int = 443) -> str:
    """Enumerate SSL/TLS protocols, ciphers and cert details with sslscan."""
    target, host, err = _guard(target)
    return err or _run(["sslscan", "--no-colour", f"{host}:{int(port)}"])


@mcp.tool()
def testssl_scan(target: str, port: int = 443) -> str:
    """Check TLS config/vulnerabilities (fast mode) with testssl.sh."""
    target, host, err = _guard(target)
    return err or _run(["testssl.sh", "--fast", "--color", "0", f"{host}:{int(port)}"],
                       timeout=max(SCAN_TIMEOUT, 600))


# ===========================================================================
#  SMB / Windows / network services (scope-checked)
# ===========================================================================
@mcp.tool()
def enum4linux_scan(target: str) -> str:
    """Full SMB/Windows enumeration via enum4linux-ng."""
    target, host, err = _guard(target)
    return err or _run(["enum4linux-ng", "-A", host], timeout=max(SCAN_TIMEOUT, 600))


@mcp.tool()
def smbmap_scan(target: str) -> str:
    """Enumerate SMB shares and access levels with smbmap (null session)."""
    target, host, err = _guard(target)
    return err or _run(["smbmap", "-H", host])


@mcp.tool()
def smb_list_shares(target: str) -> str:
    """List SMB shares via smbclient using a null session."""
    target, host, err = _guard(target)
    return err or _run(["smbclient", "-L", f"//{host}/", "-N"])


@mcp.tool()
def netexec_smb(target: str, username: str = "", password: str = "") -> str:
    """SMB enumeration / credential check with NetExec (nxc). Empty creds = null session."""
    target, host, err = _guard(target)
    return err or _run(["nxc", "smb", host, "-u", _arg(username) if username else "", "-p", password])


@mcp.tool()
def nbtscan_scan(target: str) -> str:
    """Scan for NetBIOS names/info with nbtscan (host or CIDR)."""
    target, host, err = _guard(target)
    return err or _run(["nbtscan", host])


# ===========================================================================
#  SNMP (scope-checked)
# ===========================================================================
def _snmp_communities_file():
    path = "/tmp/snmp_comm.txt"
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write("\n".join(["public", "private", "community", "manager", "admin",
                               "cisco", "default", "read", "write"]))
    return path


@mcp.tool()
def snmp_enum(target: str, community: str = "public", version: str = "2c") -> str:
    """Walk SNMP with snmpwalk. version: 1|2c."""
    target, host, err = _guard(target)
    if err:
        return err
    v = version if version in ("1", "2c") else "2c"
    return _run(["snmpwalk", f"-v{v}", "-c", _arg(community), host], timeout=max(SCAN_TIMEOUT, 300))


@mcp.tool()
def snmp_bruteforce_community(target: str) -> str:
    """Brute-force SNMP community strings with onesixtyone."""
    target, host, err = _guard(target)
    return err or _run(["onesixtyone", "-c", _snmp_communities_file(), host], timeout=120)


# ===========================================================================
#  ACTIVE DIRECTORY (scope-checked; dual-use, authorized engagements)
# ===========================================================================
@mcp.tool()
def kerbrute_userenum(domain: str, dc_ip: str, userlist: str = "default") -> str:
    """Enumerate valid AD users via Kerberos pre-auth (kerbrute). userlist: default|names."""
    _, host, err = _guard(dc_ip)
    return err or _run(["kerbrute", "userenum", "--dc", host, "-d", _arg(domain), _user_wl(userlist)],
                       timeout=max(SCAN_TIMEOUT, 600))


@mcp.tool()
def asrep_roast(domain: str, dc_ip: str, userlist: str = "default") -> str:
    """AS-REP roast accounts without Kerberos pre-auth (impacket GetNPUsers). Returns hashcat hashes."""
    _, host, err = _guard(dc_ip)
    return err or _run(["impacket-GetNPUsers", f"{_arg(domain)}/", "-dc-ip", host,
                        "-usersfile", _user_wl(userlist), "-no-pass", "-request", "-format", "hashcat"],
                       timeout=max(SCAN_TIMEOUT, 600))


@mcp.tool()
def kerberoast(domain: str, dc_ip: str, username: str, password: str) -> str:
    """Request SPN service-ticket hashes for offline cracking (impacket GetUserSPNs)."""
    _, host, err = _guard(dc_ip)
    return err or _run(["impacket-GetUserSPNs", f"{_arg(domain)}/{_arg(username)}:{password}",
                        "-dc-ip", host, "-request"], timeout=max(SCAN_TIMEOUT, 600))


@mcp.tool()
def secretsdump(target: str, username: str, password: str, domain: str = "") -> str:
    """Dump SAM/LSA/NTDS secrets via impacket-secretsdump (needs valid creds)."""
    target, host, err = _guard(target)
    if err:
        return err
    authdom = f"{_arg(domain)}/" if domain else ""
    return _run(["impacket-secretsdump", f"{authdom}{_arg(username)}:{password}@{host}"],
                timeout=max(SCAN_TIMEOUT, 600))


@mcp.tool()
def ldap_search(target: str, base_dn: str, filter: str = "(objectClass=*)",
                username: str = "", password: str = "") -> str:
    """LDAP query via ldapsearch (anonymous unless creds supplied)."""
    target, host, err = _guard(target)
    if err:
        return err
    # AD/Samba require encryption for simple binds -> use LDAPS, accept the self-signed cert.
    cmd = ["env", "LDAPTLS_REQCERT=never", "ldapsearch", "-x", "-o", "ldif-wrap=no",
           "-H", f"ldaps://{host}", "-b", _arg(base_dn)]
    if username:
        cmd += ["-D", _arg(username), "-w", password]
    cmd += [filter]
    return _run(cmd, timeout=max(SCAN_TIMEOUT, 300))


@mcp.tool()
def bloodhound_collect(domain: str, dc_ip: str, username: str, password: str, dc_host: str = "") -> str:
    """Collect AD data for BloodHound (bloodhound-python). Saves a zip to /workspace/bloodhound.
    dc_host = DC FQDN (e.g. dc1.corp.local) - bloodhound requires an FQDN, not an IP."""
    _, host, err = _guard(dc_ip)
    if err:
        return err
    out = _ws_dir("bloodhound") or "/tmp"
    dc = _arg(dc_host) if dc_host else host
    return _run(["bloodhound-python", "-d", _arg(domain), "-u", _arg(username), "-p", password,
                 "-dc", dc, "-ns", host, "-c", "All", "--zip", "--use-ldaps"],
                timeout=max(SCAN_TIMEOUT, 900), cwd=out)


@mcp.tool()
def certipy_find(target: str, username: str, password: str, domain: str) -> str:
    """Find AD CS misconfigurations / vulnerable templates (certipy find)."""
    target, host, err = _guard(target)
    return err or _run(["certipy-ad", "find", "-u", f"{_arg(username)}@{_arg(domain)}",
                        "-p", password, "-dc-ip", host, "-stdout"], timeout=max(SCAN_TIMEOUT, 600))


# ===========================================================================
#  AUTH brute force + offline cracking
# ===========================================================================
@mcp.tool()
def hydra_bruteforce(target: str, service: str, username: str = "", userlist: str = "default",
                     password: str = "", passlist: str = "default") -> str:
    """Online login brute-force with hydra. service: ssh|ftp|smb|rdp|mysql|http-get|...
    Provide username OR userlist (default|names) and password OR passlist (default|top100|rockyou)."""
    target, host, err = _guard(target)
    if err:
        return err
    cmd = ["hydra"]
    cmd += (["-l", _arg(username)] if username else ["-L", _user_wl(userlist)])
    cmd += (["-p", password] if password else ["-P", _pass_wl(passlist)])
    cmd += ["-t", "4", "-f", "-I", host, _arg(service)]
    return _run(cmd, timeout=max(SCAN_TIMEOUT, 600))


@mcp.tool()
def john_crack(hashes: str, hash_format: str = "", wordlist: str = "rockyou") -> str:
    """Crack password hashes offline with John the Ripper (one hash per line)."""
    if not hashes.strip():
        return "[error] provide one or more hashes (one per line)."
    path = "/tmp/jtr_hashes.txt"
    with open(path, "w") as f:
        f.write(hashes.strip() + "\n")
    fmt = ([f"--format={_arg(hash_format)}"] if hash_format else [])
    crack = _run(["john", f"--wordlist={_pass_wl(wordlist)}", *fmt, path], timeout=max(SCAN_TIMEOUT, 600))
    shown = _run(["john", "--show", *fmt, path], timeout=60)
    return f"{crack}\n\n--- cracked ---\n{shown}"


@mcp.tool()
def hashid_identify(hash: str) -> str:
    """Identify the likely type(s) of a password hash with hashid (incl. hashcat/john modes)."""
    h = (hash.strip().splitlines() or [""])[0]
    if not h:
        return "[error] provide a hash."
    return _run(["hashid", "-m", h], timeout=30)


# ===========================================================================
#  WORDLIST GENERATION
# ===========================================================================
@mcp.tool()
def cewl_wordlist(target: str, depth: int = 2, min_length: int = 5) -> str:
    """Build a custom wordlist by spidering a site (cewl); saved under /workspace/wordlists."""
    target, host, err = _guard(target)
    if err:
        return err
    out = os.path.join(_ws_dir("wordlists") or "/tmp", f"cewl-{host}.txt")
    res = _run(["cewl", _url(target, host), "-d", str(int(depth)), "-m", str(int(min_length)), "-w", out],
               timeout=max(SCAN_TIMEOUT, 300))
    return f"{res}\n\nSaved wordlist: {out}"


@mcp.tool()
def crunch_wordlist(min_len: int, max_len: int, charset: str = "abcdefghijklmnopqrstuvwxyz0123456789",
                    max_lines: int = 100000) -> str:
    """Generate a wordlist with crunch (capped at max_lines); saved under /workspace/wordlists."""
    out = os.path.join(_ws_dir("wordlists") or "/tmp", f"crunch-{int(min_len)}-{int(max_len)}.txt")
    res = _run(["bash", "-c",
                f"crunch {int(min_len)} {int(max_len)} {shlex.quote(charset)} 2>/dev/null | "
                f"head -n {int(max_lines)} > {shlex.quote(out)}; wc -l {shlex.quote(out)}"], timeout=120)
    return f"{res}\nSaved: {out}"


# ===========================================================================
#  SCREENSHOTS (AI-native visual triage)
# ===========================================================================
@mcp.tool()
def screenshot_web(target: str) -> str:
    """Screenshot a web service with gowitness; saves PNG(s) under /workspace/screenshots so Claude can view them."""
    target, host, err = _guard(target)
    if err:
        return err
    d = _ws_dir("screenshots")
    if not d:
        return "[error] /workspace not mounted/writable - cannot save screenshots."
    url = _url(target, host)
    res = _run(["gowitness", "scan", "single", "-u", url, "--screenshot-path", d,
                "--chrome-path", "/usr/bin/chromium", "--write-none"], timeout=180)
    imgs = sorted(os.path.join("/workspace/screenshots", f)
                  for f in os.listdir(d) if f.lower().endswith((".png", ".jpg", ".jpeg")))
    return f"{res}\n\nScreenshots ({len(imgs)}):\n" + "\n".join(imgs[-15:])


@mcp.tool()
def screenshot_hosts(targets: str) -> str:
    """Screenshot MULTIPLE web targets with gowitness. targets = comma/space-separated hosts/URLs;
    each is scope-checked. PNGs are saved under /workspace/screenshots for visual triage."""
    d = _ws_dir("screenshots")
    if not d:
        return "[error] /workspace not mounted/writable - cannot save screenshots."
    urls, blocked = [], []
    for t in re.split(r"[\s,]+", targets.strip()):
        if not t:
            continue
        ct, host, err = _guard(t)
        if err:
            blocked.append(t)
        else:
            urls.append(_url(ct, host))
    if not urls:
        return "[blocked] no in-scope targets (blocked: " + ", ".join(blocked) + ")"
    listfile = "/tmp/gw_targets.txt"
    with open(listfile, "w") as f:
        f.write("\n".join(urls) + "\n")
    res = _run(["gowitness", "scan", "file", "-f", listfile, "--screenshot-path", d,
                "--chrome-path", "/usr/bin/chromium", "--write-none"], timeout=max(SCAN_TIMEOUT, 300))
    imgs = sorted(os.path.join("/workspace/screenshots", f)
                  for f in os.listdir(d) if f.lower().endswith((".png", ".jpg", ".jpeg")))
    out = f"{res}\n\nScreenshots ({len(imgs)}):\n" + "\n".join(imgs[-25:])
    if blocked:
        out += "\n\nSkipped (out of scope): " + ", ".join(blocked)
    return out


@mcp.tool()
def winrm_exec(target: str, username: str, password: str, command: str) -> str:
    """Execute a command over an authenticated WinRM session against an AUTHORIZED Windows host
    (the non-interactive form of an evil-winrm session) via NetExec. evil-winrm is also installed
    in the image for manual interactive shells."""
    target, host, err = _guard(target)
    if err:
        return err
    return _run(["nxc", "winrm", host, "-u", _arg(username), "-p", password, "-x", command],
                timeout=max(SCAN_TIMEOUT, 300))


@mcp.tool()
def trivy_scan(target: str, scan_type: str = "image") -> str:
    """Cloud-native / container / IaC security scan with Trivy (vulnerabilities + misconfig + secrets).
    scan_type: image (container image, e.g. nginx:latest) | fs (a path) | repo (git URL) |
    config (IaC: Terraform/Kubernetes/Dockerfile). Target is an artifact, not a host, so it is not
    scope-checked. For full AWS/Azure/GCP account audits use 'trivy aws/azure' with creds, or prowler."""
    st = scan_type if scan_type in ("image", "fs", "repo", "config") else "image"
    return _run(["trivy", st, "--scanners", "vuln,misconfig,secret", "--no-progress", "-q",
                 _sanitize(target)], timeout=max(SCAN_TIMEOUT, 600))


# ===========================================================================
#  ENGAGEMENT WORKSPACE / REPORTING
# ===========================================================================
@mcp.tool()
def save_finding(title: str, severity: str = "medium", target: str = "",
                 detail: str = "", evidence: str = "", cvss: str = "", cwe: str = "",
                 endpoint: str = "", request: str = "", response: str = "",
                 remediation: str = "") -> str:
    """Record a finding to /workspace/findings.jsonl for later reporting.
    severity: info|low|medium|high|critical. Optional (for richer HackerOne reports):
    cvss (a v3.1 vector — score is auto-computed), cwe (e.g. CWE-639), endpoint,
    request/response (raw repro evidence), remediation."""
    d = _ws_dir()
    if not d:
        return "[error] /workspace not available."
    rec = {"ts": datetime.datetime.now().isoformat(timespec="seconds"), "title": title,
           "severity": severity, "target": target, "detail": detail, "evidence": evidence}
    if cvss:
        rec["cvss"] = cvss.strip()
        try:
            rec["cvss_score"], rec["cvss_severity"] = _cvss31_base(cvss)
        except Exception:  # noqa: BLE001
            pass
    for k, v in (("cwe", cwe), ("endpoint", endpoint), ("request", request),
                 ("response", response), ("remediation", remediation)):
        if v:
            rec[k] = v
    with open(os.path.join(d, "findings.jsonl"), "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")
    extra = f" CVSS {rec['cvss_score']}" if rec.get("cvss_score") else ""
    return f"Saved finding: [{severity}] {title}{extra}"


@mcp.tool()
def list_findings() -> str:
    """Show all findings recorded in the workspace."""
    d = _ws_dir()
    if not d:
        return "[error] /workspace not available."
    p = os.path.join(d, "findings.jsonl")
    if not os.path.exists(p):
        return "No findings recorded yet."
    with open(p, encoding="utf-8") as f:
        return f.read().strip() or "No findings recorded yet."


@mcp.tool()
def generate_report(title: str = "Penetration Test Report") -> str:
    """Compile recorded findings into a markdown report at /workspace/report.md."""
    d = _ws_dir()
    if not d:
        return "[error] /workspace not available."
    findings = []
    p = os.path.join(d, "findings.jsonl")
    if os.path.exists(p):
        for line in open(p, encoding="utf-8"):
            line = line.strip()
            if line:
                try:
                    findings.append(json.loads(line))
                except Exception:
                    pass
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda r: order.get(str(r.get("severity", "")).lower(), 5))
    counts = {}
    for r in findings:
        counts[r.get("severity", "?")] = counts.get(r.get("severity", "?"), 0) + 1
    md = [f"# {title}", "", f"Generated: {datetime.datetime.now().isoformat(timespec='seconds')}",
          f"Scope: {_scope_str()}", "", "## Summary", "", f"Total findings: {len(findings)}"]
    md += [f"- {s}: {c}" for s, c in counts.items()]
    md += ["", "## Findings", ""]
    for i, r in enumerate(findings, 1):
        md += [f"### {i}. [{str(r.get('severity', '?')).upper()}] {r.get('title', '')}", "",
               f"- Target: {r.get('target', '')}", f"- When: {r.get('ts', '')}", "",
               r.get("detail", "")]
        if r.get("evidence"):
            md += ["", "```", r["evidence"], "```"]
        md += [""]
    out = os.path.join(d, "report.md")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    return f"Report written to {out}\n\n" + "\n".join(md)[:4000]


@mcp.tool()
def workspace_info() -> str:
    """Show the workspace path, whether it's writable, and its files."""
    d = _ws_dir()
    files = []
    if d and os.path.isdir(d):
        for root, _dirs, fns in os.walk(d):
            for fn in fns:
                files.append(os.path.join(root, fn).replace(d, "/workspace"))
    return (f"Workspace: {WORKSPACE} (writable={_ws_available()})\n"
            f"Files ({len(files)}):\n" + "\n".join(sorted(files)[:100]))


# ===========================================================================
#  METASPLOIT (via msfrpcd RPC service on the lab network)
# ===========================================================================
MSF_HOST = os.environ.get("MSF_HOST", "msf")
MSF_PORT = int(os.environ.get("MSF_PORT", "55553"))
MSF_PASSWORD = os.environ.get("MSF_PASSWORD", "redmcp_msf")


def _audit(msg: str):
    d = _ws_dir()
    if not d:
        return
    try:
        with open(os.path.join(d, "audit.log"), "a", encoding="utf-8") as f:
            f.write(f"{datetime.datetime.now().isoformat(timespec='seconds')} {msg}\n")
    except Exception:
        pass


def _msf_console_run(commands, timeout=180) -> str:
    """Run commands in a fresh msf console via RPC and collect the output."""
    from pymetasploit3.msfrpc import MsfRpcClient
    client = MsfRpcClient(MSF_PASSWORD, server=MSF_HOST, port=MSF_PORT, ssl=False)
    con = client.consoles.console()
    try:
        con.read()  # drain banner
        for c in commands:
            con.write(c + "\n")
        out, deadline = "", time.time() + timeout
        while time.time() < deadline:
            r = con.read()
            out += r.get("data", "")
            if not r.get("busy"):
                time.sleep(0.4)
                r2 = con.read()
                out += r2.get("data", "")
                if not r2.get("busy"):
                    break
            time.sleep(0.4)
        return out.strip() or "(no output)"
    finally:
        try:
            con.destroy()
        except Exception:
            pass


@mcp.tool()
def msf_search(query: str) -> str:
    """Search Metasploit modules (read-only). e.g. 'eternalblue' or 'type:exploit smb'."""
    try:
        q = _searchq(query)
    except ValueError as e:
        return f"[error] {e}"
    try:
        return _msf_console_run([f"search {q}"], timeout=90)
    except Exception as e:  # noqa: BLE001
        return f"[error] MSF RPC unavailable: {e} (start it: docker compose -f lab/msf-compose.yml up -d)"


@mcp.tool()
def msf_module_info(module: str) -> str:
    """Show a Metasploit module's description, options and targets (read-only)."""
    if not re.fullmatch(r"(?:auxiliary|exploit|post|payload|encoder|nop|evasion)/[A-Za-z0-9_/-]+", module):
        return "[blocked] invalid module name"
    try:
        return _msf_console_run([f"info {module}"], timeout=60)
    except Exception as e:  # noqa: BLE001
        return f"[error] MSF RPC unavailable: {e}"


@mcp.tool()
def msf_run(module: str, rhosts: str, options: str = "", confirm: str = "") -> str:
    """Run a Metasploit aux/exploit module against an AUTHORIZED target.
    GATED: requires confirm="RUN". rhosts is scope-checked and the run is audit-logged.
    options: only RPORT=<1..65535>, SSL=true|false, STOP_ON_SUCCESS=true|false.
    Target overrides, payload options and console-command injection are blocked."""
    _, host, err = _guard(rhosts)
    if err:
        return err
    if confirm != "RUN":
        return ('[blocked] exploitation is gated. Re-call with confirm="RUN" to authorize '
                f'running {module} against {host}.')
    if not re.fullmatch(r"(?:auxiliary|exploit|post)/[A-Za-z0-9_/-]+", module):
        return "[blocked] invalid module name"
    cmds = [f"use {module}", f"set RHOSTS {host}"]
    try:
        for kv in shlex.split(options):
            key, sep, value = kv.partition("=")
            key = key.upper()
            if not sep or key not in {"RPORT", "SSL", "STOP_ON_SUCCESS"}:
                return "[blocked] only RPORT, SSL and STOP_ON_SUCCESS options are permitted"
            if key == "RPORT":
                if not value.isdigit() or not 1 <= int(value) <= 65535:
                    return "[blocked] invalid RPORT"
            elif value.lower() not in {"true", "false"}:
                return "[blocked] boolean option must be true or false"
            cmds.append(f"set {key} {value}")
    except ValueError:
        return "[blocked] malformed options"
    cmds.append("run")
    _audit(f"msf_run module={module} rhosts={host} options={options!r}")
    try:
        return _msf_console_run(cmds, timeout=max(SCAN_TIMEOUT, 300))
    except Exception as e:  # noqa: BLE001
        return f"[error] MSF RPC unavailable: {e}"


# ===========================================================================
#  EXPLOIT SEARCH + SCOPE
# ===========================================================================
@mcp.tool()
def searchsploit_lookup(query: str) -> str:
    """Search the local Exploit-DB (searchsploit). No network / no target."""
    terms = [t for t in re.split(r"\s+", query.strip()) if t and _SAFE.match(t)]
    if not terms:
        return "[error] provide one or more search terms."
    return _run(["searchsploit", *terms], timeout=60)


@mcp.tool()
def list_wordlists() -> str:
    """List wordlist aliases available to the fuzzing/brute-force tools."""
    out = ["WEB:"] + [f"  {k} -> {v}" for k, v in WEB_WORDLISTS.items()]
    out += ["USERS:"] + [f"  {k} -> {v}" for k, v in USER_WORDLISTS.items()]
    out += ["PASSWORDS:"] + [f"  {k} -> {v}" for k, v in PASS_WORDLISTS.items()]
    return "\n".join(out)


@mcp.tool()
def authorized_scope() -> str:
    """Show the currently configured authorized target allowlist (engagement scope)."""
    if not ALLOW_NETS and not ALLOW_HOSTS:
        return ("No scope configured. Set KALI_TARGET_ALLOWLIST (comma-separated CIDRs "
                "and/or hostnames). All active tools are blocked until you do.")
    return _scope_str()


# ===========================================================================
#  CVSS v3.1 (Tier 5) - base-score calculator (verified against FIRST spec)
# ===========================================================================
_CVSS_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_CVSS_AC = {"L": 0.77, "H": 0.44}
_CVSS_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27},
            "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
_CVSS_UI = {"N": 0.85, "R": 0.62}
_CVSS_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _cvss_roundup(value: float) -> float:
    import math
    i = round(value * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000.0) + 1) / 10.0


def _cvss_severity(score: float) -> str:
    if score == 0.0:
        return "None"
    if score <= 3.9:
        return "Low"
    if score <= 6.9:
        return "Medium"
    if score <= 8.9:
        return "High"
    return "Critical"


def _cvss31_base(vector: str):
    m = {}
    for part in vector.strip().split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            k = k.strip().upper()
            if k != "CVSS":
                m[k] = v.strip().upper()
    for r in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
        if r not in m:
            raise ValueError(f"missing base metric {r}")
    scope = m["S"]
    if scope not in ("U", "C"):
        raise ValueError("invalid Scope value")
    av, ac = _CVSS_AV[m["AV"]], _CVSS_AC[m["AC"]]
    pr, ui = _CVSS_PR[scope][m["PR"]], _CVSS_UI[m["UI"]]
    c, i, a = _CVSS_CIA[m["C"]], _CVSS_CIA[m["I"]], _CVSS_CIA[m["A"]]
    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    impact = (6.42 * iss if scope == "U"
              else 7.52 * (iss - 0.029) - 3.25 * ((iss * 0.9731 - 0.02) ** 13))  # v3.1 changed-scope
    expl = 8.22 * av * ac * pr * ui
    if impact <= 0:
        score = 0.0
    elif scope == "U":
        score = _cvss_roundup(min(impact + expl, 10.0))
    else:
        score = _cvss_roundup(min(1.08 * (impact + expl), 10.0))
    return score, _cvss_severity(score)


# ===========================================================================
#  INTEL REGEXES (Tier 2) - endpoint + secret extraction (stdlib only)
# ===========================================================================
_LINKFINDER_REGEX = re.compile(
    r"""(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})"""
    r"""|((?:/|\.\./|\./)[^"'><,;| *()(%$^/\\\[\]][^"'><,;|()]{1,})"""
    r"""|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/.]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))"""
    r"""|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))"""
    r"""|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|']{0,}|)))(?:"|')"""
)

_SECRET_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("AWS Secret Key", re.compile(r"(?i)aws.{0,20}?secret.{0,20}?['\"]([A-Za-z0-9/+=]{40})['\"]")),
    ("Google API Key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")),
    ("Slack Token", re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b")),
    ("Private Key (PEM)", re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----)")),
    ("JWT", re.compile(r"\b(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b")),
    ("Bearer Token", re.compile(r"(?i)\bBearer\s+([A-Za-z0-9_\-.=/+]{8,})")),
    ("Generic Secret", re.compile(
        r"""(?i)\b(?:api[_-]?key|apikey|secret|passwd|password|access[_-]?token|client[_-]?secret|token)\b"""
        r"""\s*[:=]\s*['\"]([^'\"\s]{6,})['\"]""")),
    ("Google OAuth", re.compile(r"\b([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)\b")),
]


def _secret_redact(v: str) -> str:
    v = str(v).strip()
    n = len(v)
    if n <= 8:
        return (v[0] + "*" * (n - 1)) if n > 1 else "*"
    keep = 4 if n >= 16 else 2
    return v[:keep] + "*" * (n - 2 * keep) + v[-keep:]


def _find_endpoints(text: str):
    seen, out = set(), []
    for mt in _LINKFINDER_REGEX.finditer(text):
        e = (mt.group(1) or "").strip()
        if e and e not in seen and len(e) < 300:
            seen.add(e)
            out.append(e)
    return out


def _find_secrets(text: str):
    out, seen = [], set()
    for name, rx in _SECRET_PATTERNS:
        for mt in rx.finditer(text):
            raw = mt.group(1) if mt.groups() else mt.group(0)
            red = _secret_redact(raw)
            key = (name, red)
            if key not in seen:
                seen.add(key)
                out.append({"type": name, "match": red})
    return out


# ===========================================================================
#  HTTP CORE (Tier 1/2/6) - scoped, attributed, rate-limited, evidence-logged
# ===========================================================================
_http_lock = threading.Lock()
_http_last = {}  # host -> last request monotonic timestamp
_TEXT_CT = ("text/", "application/json", "application/xml", "application/javascript",
            "application/x-www-form-urlencoded", "application/xhtml", "+json", "+xml", "graphql")


def _rate_limit(host: str):
    if HTTP_MIN_INTERVAL <= 0:
        return
    with _http_lock:
        now = time.monotonic()
        wait = HTTP_MIN_INTERVAL - (now - _http_last.get(host, 0.0))
        # reserve this host's slot before releasing the lock, so a sleep for one
        # host does not block concurrent requests to a different host
        _http_last[host] = now + (wait if wait > 0 else 0.0)
    if wait > 0:
        time.sleep(wait)


def _ev_dir():
    return _ws_dir("evidence") or "/tmp"


def _save_evidence(name: str, content) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:120]
    base = os.path.join(_ev_dir(), f"{safe}-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')}")
    try:
        if isinstance(content, bytes):
            with open(base + ".bin", "wb") as f:
                f.write(content)
            return base + ".bin"
        with open(base + ".txt", "w", encoding="utf-8", errors="replace") as f:
            f.write(content)
        return base + ".txt"
    except Exception:  # noqa: BLE001
        return ""


_SENSITIVE_HDRS = ("authorization", "proxy-authorization", "cookie", "set-cookie",
                   "x-api-key", "api-key", "x-auth-token", "x-amz-security-token")


def _sensitive_header(name: str) -> bool:
    """Conservatively classify credentials; custom headers are never forwarded cross-origin."""
    name = str(name).lower()
    return name in _SENSITIVE_HDRS or any(part in name for part in
                                         ("token", "secret", "password", "api-key", "apikey"))


def _redact_auth(headers: dict) -> dict:
    return {k: ("[REDACTED]" if _sensitive_header(k) else
                _display_http_url(str(v)) if k.lower() in {"location", "referer", "referrer"} else v)
            for k, v in headers.items()}


def _http_origin(url: str):
    """Validate HTTP URLs before scope checks or transport; never allow URL credentials."""
    p = urlparse(url)
    if (p.scheme.lower() not in {"http", "https"} or not p.hostname or
            p.username is not None or p.password is not None or
            any(ord(c) < 33 or ord(c) == 127 for c in url)):
        raise ValueError("expected an HTTP(S) URL without userinfo or control characters")
    # Accessing port validates malformed/out-of-range port strings.
    port = p.port
    if port == 0:
        raise ValueError("HTTP port must be between 1 and 65535")
    return p.scheme.lower(), p.hostname.lower(), port or (443 if p.scheme.lower() == "https" else 80)


def _display_http_url(url: str) -> str:
    """Avoid persisting tokens in query strings or fragments (paths may still be sensitive)."""
    try:
        p = urlparse(url)
        netloc = p.netloc.rsplit("@", 1)[-1]
        return p._replace(netloc=netloc, query="[REDACTED]" if p.query else "", fragment="").geturl()
    except ValueError:
        return "[invalid URL]"


def _http_credentials(*header_sets):
    values = set()
    for headers in header_sets:
        for name, value in headers.items():
            if not _sensitive_header(name):
                continue
            value = str(value)
            if value:
                values.add(value)
            if name.lower() in {"authorization", "proxy-authorization"} and " " in value:
                values.add(value.split(" ", 1)[1])
            if name.lower() in {"cookie", "set-cookie"}:
                for part in value.split(";"):
                    if "=" in part:
                        values.add(part.split("=", 1)[1].strip())
    return sorted((v for v in values if v), key=len, reverse=True)


def _credential_prefix_at_end(text: str, credential: str) -> int:
    """Length of a credential prefix cut at the end of a captured body, in linear time."""
    if not text or not credential:
        return 0
    prefix = [0] * len(credential)
    for index in range(1, len(credential)):
        matched = prefix[index - 1]
        while matched and credential[index] != credential[matched]:
            matched = prefix[matched - 1]
        if credential[index] == credential[matched]:
            matched += 1
        prefix[index] = matched
    matched = 0
    for char in text[-len(credential):]:
        while matched and (matched == len(credential) or char != credential[matched]):
            matched = prefix[matched - 1]
        if char == credential[matched]:
            matched += 1
    return matched if matched < len(credential) else 0


def _redact_http_text(text: str, credentials, incomplete=False) -> str:
    if not credentials:
        return text
    # Mask a token cut by the byte cap/read error before replacing complete tokens.
    # A conservative short-prefix match is preferable to leaking part of a credential.
    if incomplete:
        trailing = max((_credential_prefix_at_end(text, value) for value in credentials), default=0)
        if trailing:
            text = text[:-trailing] + "[REDACTED]"
    # One pass avoids re-redacting markers (or multiplying output for short secrets).
    pattern = "|".join(re.escape(value) for value in credentials)
    return re.sub(pattern, "[REDACTED]", text)


def _redact_http_data(value, credentials, redact_keys=False):
    if isinstance(value, str):
        return _redact_http_text(value, credentials)
    if isinstance(value, dict):
        return {(_redact_http_text(str(k), credentials) if redact_keys else k):
                _redact_http_data(v, credentials, redact_keys=True) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_http_data(v, credentials, redact_keys=True) for v in value]
    return value


def _read_capped(resp, deadline):
    """Bound retained bytes exactly and report incomplete reads; always close the response.

    The deadline is checked between reads. A currently blocked socket read is bounded by
    the requests read timeout, not interrupted by this check.
    """
    buf = bytearray()
    reason, read_error = "", ""
    try:
        for chunk in resp.iter_content(chunk_size=min(8192, MAX_BODY_BYTES + 1)):
            if time.monotonic() >= deadline:
                reason = "deadline"
                break
            if not chunk:
                continue
            remaining = MAX_BODY_BYTES - len(buf)
            buf.extend(chunk[:remaining])
            if len(chunk) > remaining:
                reason = "size cap"
                break
    except Exception as exc:  # noqa: BLE001
        # Exception text can contain credential-bearing URLs; keep only the type.
        read_error = type(exc).__name__
        reason = "read error"
    finally:
        resp.close()
    return bytes(buf), reason, read_error


def _do_request(method, url, headers=None, data=None, verify=True, follow=True, timeout=None):
    """Scoped HTTP with per-hop checks, bounded capture and explicit incomplete results.

    Scope checks are not a network sandbox: DNS can change after checking. Enforce
    engagement egress rules externally as well. Environment proxies/.netrc are disabled.
    """
    import math
    import requests
    method = str(method).upper()
    if not re.fullmatch(r"[A-Z]+", method):
        raise ValueError("invalid HTTP method")
    budget = float(HTTP_TIMEOUT if timeout is None else timeout)
    if not math.isfinite(budget) or budget <= 0:
        raise ValueError("HTTP timeout must be finite and positive")
    if MAX_BODY_BYTES <= 0 or MAX_BODY_CHARS <= 0 or MAX_OUTPUT_CHARS <= 0:
        raise ValueError("HTTP capture and output limits must be positive")
    if data is not None and (not isinstance(data, (str, bytes)) or len(data) > MAX_BODY_BYTES):
        raise ValueError("HTTP request body exceeds the configured limit or has an unsupported type")
    if isinstance(data, str) and len(data.encode("utf-8")) > MAX_BODY_BYTES:
        raise ValueError("HTTP request body exceeds the configured byte limit")
    # Attribution cannot be overridden by a differently-cased caller header.
    attribution_names = {k.lower() for k in ATTRIBUTION}
    hdrs = {k: v for k, v in (headers or {}).items() if k.lower() not in attribution_names}
    hdrs.update(ATTRIBUTION)
    if any(k.lower() in {"host", "content-length", "transfer-encoding"} for k in hdrs):
        raise ValueError("Host and framing headers are managed by the HTTP transport")
    t0 = time.monotonic()
    deadline = t0 + budget
    cur, hops = url, 0
    with requests.Session() as session:
        session.trust_env = False
        # No automatic cookie jar replay: callers explicitly provide each request's credentials.
        while True:
            _http_origin(cur)
            ok, _detail = _in_scope(cur)
            if not ok:
                raise ValueError("HTTP target is outside the authorized scope")
            _rate_limit(_extract_host(cur))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("HTTP deadline reached before request")
            session.cookies.clear()
            resp = session.request(method, cur, headers=hdrs, data=data, verify=verify,
                                   allow_redirects=False, stream=True, timeout=remaining)
            if follow and resp.is_redirect:
                loc = resp.headers.get("Location", "")
                status = resp.status_code
                resp.close()
                nxt = urljoin(cur, loc)
                blocked = ""
                try:
                    old_origin, new_origin = _http_origin(cur), _http_origin(nxt)
                    ok, _detail = _in_scope(nxt)
                    if not ok:
                        blocked = "redirect target is outside the authorized scope"
                    elif hops >= 8:
                        blocked = "redirect limit reached"
                    elif old_origin[0] == "https" and new_origin[0] != "https":
                        blocked = "HTTPS downgrade redirect refused"
                    elif old_origin != new_origin and data:
                        blocked = "cross-origin redirect with request body refused"
                except ValueError:
                    blocked = "invalid redirect URL"
                if blocked:
                    return {"status": status, "reason": "redirect blocked", "url": cur,
                            "req_headers": hdrs, "resp_headers": {}, "ct": "text/plain",
                            "is_text": True, "truncated": False, "blocked": True,
                            "complete": False, "truncation_reason": blocked, "read_error": "",
                            "bytes": ("[blocked] " + blocked).encode(), "len": 0,
                            "ms": int((time.monotonic() - t0) * 1000)}
                if old_origin != new_origin:
                    # A finite secret-header list cannot cover arbitrary application credentials.
                    hdrs = {k: v for k, v in ATTRIBUTION.items() if not _sensitive_header(k)}
                if (status == 303 and method != "HEAD") or (status in {301, 302} and method == "POST"):
                    method, data = "GET", None
                    hdrs = {k: v for k, v in hdrs.items() if k.lower() not in
                            {"content-type", "content-encoding"}}
                cur, hops = nxt, hops + 1
                continue
            body, reason, read_error = _read_capped(resp, deadline)
            ct = resp.headers.get("Content-Type", "")
            is_text = (not ct) or any(m in ct.lower() for m in _TEXT_CT)
            return {"status": resp.status_code, "reason": resp.reason, "url": resp.url,
                    "req_headers": hdrs, "resp_headers": dict(resp.headers), "ct": ct,
                    "is_text": is_text, "len": len(body), "bytes": body,
                    "ms": int((time.monotonic() - t0) * 1000), "truncated": bool(reason),
                    "complete": not reason, "truncation_reason": reason, "read_error": read_error}


def _save_http_evidence(content, binary=False):
    """Create private evidence exclusively inside the workspace; never fall back to /tmp."""
    import tempfile
    try:
        directory = _ws_path("evidence")
        os.makedirs(directory, mode=0o700, exist_ok=True)
        fd, path = tempfile.mkstemp(prefix="http-", suffix=".bin" if binary else ".json", dir=directory)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content if binary else content.encode("utf-8"))
        return path
    except (OSError, ValueError):
        return ""


# ===========================================================================
#  AUTHENTICATED API / AUTH-LOGIC (Tier 1)
# ===========================================================================
@mcp.tool()
def http_request(url: str, method: str = "GET", headers: str = "", body: str = "",
                 token: str = "", content_type: str = "", verify_tls: bool = True,
                 follow_redirects: bool = True) -> str:
    """Scoped HTTP with redacted metadata evidence and capped response preview.

    Bodies are not retained by default. HTTP_SAVE_BODY_EVIDENCE=1 opts into retaining
    bodies in mode-0600 files: known header credentials are masked in text, but unknown
    secrets and raw binary content require operator review. headers: 'K: V; K2: V2'.
    token: adds 'Authorization: Bearer <token>'. TLS verification defaults on; disable
    explicitly only for a self-signed service in an owned/authorized isolated lab.
    """
    target, host, err = _guard(url)
    if err:
        return err
    if "://" not in url:
        url = "http://" + url
    hdrs = _parse_headers_spec(headers)
    if token and not any(k.lower() == "authorization" for k in hdrs):
        hdrs["Authorization"] = f"Bearer {token.strip()}"
    if content_type:
        hdrs["Content-Type"] = content_type
    if len(body) > MAX_BODY_BYTES:
        return "[error] HTTP request body exceeds MAX_BODY_BYTES"
    try:
        r = _do_request(method, url, headers=hdrs, data=body.encode("utf-8") if body else None,
                        verify=verify_tls, follow=follow_redirects)
    except Exception as exc:  # noqa: BLE001
        return f"[error] request failed ({type(exc).__name__}); no complete response available"
    credentials = _http_credentials(hdrs, ATTRIBUTION, r["req_headers"], r["resp_headers"])
    clean = lambda value: _redact_http_text(str(value), credentials)
    keep_bodies = os.environ.get("HTTP_SAVE_BODY_EVIDENCE", "0") == "1"
    metadata = {"method": method.upper(), "request_url": _display_http_url(url),
                "final_url": _display_http_url(r["url"]), "status": r["status"],
                "final_request_headers": _redact_auth(r["req_headers"]),
                "response_headers": _redact_auth(r["resp_headers"]),
                "bytes_captured": r["len"], "duration_ms": r["ms"],
                "complete": r.get("complete", True), "truncation_reason": r.get("truncation_reason", ""),
                "read_error": r.get("read_error", ""), "body_retention": "opt-in" if keep_bodies else "omitted"}
    if r["is_text"]:
        import codecs
        # Do not turn a byte-cut UTF-8 credential into an unmatchable replacement suffix.
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        text = decoder.decode(r["bytes"], final=r.get("complete", True))
        text = _redact_http_text(text, credentials, incomplete=not r.get("complete", True))
        preview = text[:MAX_BODY_CHARS] + ("\n... [preview truncated]" if len(text) > MAX_BODY_CHARS else "")
        if keep_bodies:
            metadata.update(request_body=clean(body), response_body=text)
    else:
        preview = f"[binary {r['ct']} - {r['len']} bytes; not retained]"
        if keep_bodies:
            binary_path = _save_http_evidence(r["bytes"], binary=True)
            metadata["binary_path"] = binary_path
            preview = (f"[binary {r['ct']} - {r['len']} bytes saved to {binary_path}; "
                       "raw content, review before sharing]" if binary_path else "[binary evidence save failed]")
    evpath = _save_http_evidence(json.dumps(_redact_http_data(metadata, credentials), indent=2))
    rh = "\n".join(f"  {k}: {v}" for k, v in _redact_auth(r["resp_headers"]).items())
    incomplete = ("  [INCOMPLETE: " + r.get("truncation_reason", "unknown") + "]"
                  if not r.get("complete", True) else "")
    result = clean(f"HTTP {r['status']} {r['reason']}  ({r['len']} bytes, {r['ms']}ms){incomplete}"
                 f"  -> {_display_http_url(r['url'])}\n"
                 f"[request headers: {_redact_auth(r['req_headers'])}]\n"
                 f"Response headers:\n{rh}\n\n--- body ---\n{preview}\n\n"
                 f"[evidence: {evpath or 'not saved (workspace unavailable)'}; "
                 f"bodies {'opt-in' if keep_bodies else 'not retained'}]")
    if len(result) > MAX_OUTPUT_CHARS:
        marker = "\n[output truncated]"
        result = result[:max(0, MAX_OUTPUT_CHARS - len(marker))] + marker[:MAX_OUTPUT_CHARS]
    return result


def _b64url_json(part: str):
    pad = "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part + pad))


@mcp.tool()
def jwt_decode(token: str) -> str:
    """Decode a JWT's header + claims WITHOUT verifying the signature. Highlights alg/kid, exp/iat
    (as human time, and whether expired), and auth-relevant claims (aud/iss/sub/scope/roles/tenant)."""
    toks = token.strip().split()  # tolerate 'Bearer <token>'
    token = toks[-1] if toks else ""
    if not token:
        return "[error] provide a JWT."
    parts = token.split(".")
    if len(parts) < 2:
        return "[error] not a JWT (need header.payload[.signature])."
    try:
        hdr, pl = _b64url_json(parts[0]), _b64url_json(parts[1])
    except Exception as e:  # noqa: BLE001
        return f"[error] could not decode JWT: {e}"
    if not isinstance(hdr, dict) or not isinstance(pl, dict):
        return "[error] JWT header/payload are not JSON objects."
    out = [f"alg={hdr.get('alg')}  typ={hdr.get('typ')}  kid={hdr.get('kid')}"]
    now = int(time.time())
    for k in ("iat", "nbf", "exp"):
        if k in pl:
            try:
                ev = int(pl[k])
                ts = datetime.datetime.fromtimestamp(ev).isoformat()
            except Exception:  # noqa: BLE001
                ev, ts = None, str(pl[k])
            tag = ""
            if k == "exp" and ev is not None:
                tag = "  [EXPIRED]" if ev < now else f"  [{ev - now}s left]"
            out.append(f"{k}: {pl[k]} ({ts}){tag}")
    hi = {k: pl[k] for k in ("aud", "iss", "sub", "scope", "scopes", "roles", "tenant",
                             "tenant_id", "client_id", "azp", "email") if k in pl}
    out.append("header: " + json.dumps(hdr))
    out.append("claims: " + json.dumps(pl, indent=1)[:MAX_BODY_CHARS])
    if hi:
        out.append("auth-relevant: " + json.dumps(hi))
    return "\n".join(out)


@mcp.tool()
def jwt_forge(claims: str, key: str = "", alg: str = "RS256", mode: str = "sign",
              kid: str = "") -> str:
    """Craft a JWT for AUTHORIZED auth-logic testing.
    mode=sign: sign `claims` with `key` (RSA/EC PEM private key, or an HMAC secret for HS*).
    mode=none: emit an unsigned alg=none token (tests servers that don't enforce a signature).
    mode=confuse: RS->HS algorithm-confusion - HMAC(HS256)-sign with `key` set to the server's RSA
      PUBLIC key (PEM); succeeds against servers that verify HS256 using their public key as the secret.
    `claims`: a JSON object, OR an existing JWT whose claims to reuse/modify. Returns the token."""
    claims = claims.strip()
    if claims.startswith("eyJ") and claims.count(".") >= 2:
        try:
            payload = _b64url_json(claims.split(".")[1])
        except Exception as e:  # noqa: BLE001
            return f"[error] could not reuse claims from token: {e}"
    else:
        try:
            payload = json.loads(claims)
        except Exception as e:  # noqa: BLE001
            return f"[error] claims must be a JSON object or a JWT: {e}"
    if mode == "none":
        h = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=").decode()
        return f"{h}.{p}.\n\n[alg=none unsigned token]"
    try:
        import jwt as pyjwt
    except Exception:  # noqa: BLE001
        return "[error] PyJWT not installed in image (add PyJWT[crypto] to requirements)."
    headers = {"kid": kid} if kid else None
    try:
        if mode == "confuse":
            tok = pyjwt.encode(payload, key, algorithm="HS256", headers=headers)
            note = "[RS->HS confusion: HMAC-signed with the provided (public) key]"
        else:
            tok = pyjwt.encode(payload, key, algorithm=alg, headers=headers)
            note = f"[signed alg={alg}]"
    except Exception as e:  # noqa: BLE001
        return f"[error] signing failed: {e}"
    if isinstance(tok, bytes):
        tok = tok.decode()
    return f"{tok}\n\n{note}"


@mcp.tool()
def idor_probe(url: str, token_a: str = "", token_b: str = "", method: str = "GET",
               body: str = "", content_type: str = "") -> str:
    """Cross-account BOLA/IDOR harness. Requests the SAME resource (url) three ways - as the owner
    (token_a), as a different account (token_b), and unauthenticated - then diffs status/length to
    flag responses for manual review. A 2xx alone does not prove BOLA or broken authentication:
    verify object ownership, returned content, and the expected access policy. Incomplete requests
    produce an inconclusive result. Scope-checked, attributed, metadata-evidence-logged."""
    target, host, err = _guard(url)
    if err:
        return err
    if "://" not in url:
        url = "http://" + url  # keep the full path/query; don't collapse to the host root
    data = body.encode("utf-8") if body else None
    base_hdrs = {"Content-Type": content_type} if content_type else {}

    def call(tok):
        h = dict(base_hdrs)
        if tok:
            h["Authorization"] = f"Bearer {tok.strip()}"
        return _do_request(method, url, headers=h, data=data)

    rows, results = [], {}
    for label, tok in (("owner(A)", token_a), ("attacker(B)", token_b), ("unauth", "")):
        if label == "attacker(B)" and not token_b:
            continue
        try:
            r = call(tok)
            results[label] = r
            partial = " [INCOMPLETE]" if not r.get("complete", True) else ""
            rows.append(f"  {label:12} HTTP {r['status']}  {r['len']} bytes  {r['ct'] or '-'}{partial}")
        except Exception as exc:  # noqa: BLE001
            rows.append(f"  {label:12} ERROR {type(exc).__name__}")

    def ok(r):
        return r and r.get("complete", True) and 200 <= r["status"] < 300
    a, b, u = results.get("owner(A)"), results.get("attacker(B)"), results.get("unauth")
    verdict = []
    if a and b and ok(a) and ok(b):
        close = abs(a["len"] - b["len"]) <= max(50, int(0.1 * max(1, a["len"])))
        verdict.append("REVIEW REQUIRED: both account requests returned 2xx"
                       + (" with near-identical length" if close else "")
                       + "; verify actual object ownership and response content before asserting BOLA.")
    if u and ok(u):
        verdict.append("REVIEW REQUIRED: unauthenticated request returned 2xx; confirm that the returned resource requires authentication.")
    required = (a, b, u) if token_b else (a, u)
    if any(not r or not r.get("complete", True) for r in required):
        verdict.append("INCONCLUSIVE: one or more requests failed, were blocked, or returned incomplete bodies.")
    if not verdict:
        verdict.append("No cross-account access detected in these responses; this is not proof of authorization correctness.")
    display_url = _display_http_url(url)
    _save_http_evidence(json.dumps({"kind": "idor", "method": method, "url": display_url,
                                    "rows": rows, "verdict": verdict}, indent=2))
    return f"IDOR/BOLA probe: {method} {display_url}\n" + "\n".join(rows) + "\n\nVerdict:\n" + "\n".join("  " + v for v in verdict)


def _load_source_text(source: str):
    """Return (text, err). source = a /workspace file path or a URL (scope-checked)."""
    if "://" in source:
        target, host, err = _guard(source)
        if err:
            return None, err
        try:
            response = _do_request("GET", source)
            if not response.get("complete", True) or not 200 <= response["status"] < 300:
                return None, "[error] source fetch was incomplete, blocked, or unsuccessful"
            return response["bytes"].decode("utf-8", "replace"), None
        except Exception as exc:  # noqa: BLE001
            return None, f"[error] fetch failed ({type(exc).__name__})"
    try:
        p = _ws_path(source)
    except ValueError as e:
        return None, f"[error] {e}"
    if not os.path.isfile(p):
        return None, f"[error] file not found in workspace: {source}"
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            return f.read(), None
    except Exception as e:  # noqa: BLE001
        return None, f"[error] {e}"


@mcp.tool()
def api_ingest(source: str) -> str:
    """Parse an OpenAPI/Swagger (JSON or YAML) or Postman collection into a flat endpoint inventory
    (METHOD path - params/auth) so every endpoint can be systematically tested for authz gaps.
    source: a /workspace file path or a URL (scope-checked). Saves the full inventory to /workspace."""
    text, err = _load_source_text(source)
    if err:
        return err
    doc = None
    try:
        doc = json.loads(text)
    except Exception:  # noqa: BLE001
        try:
            import yaml
            doc = yaml.safe_load(text)
        except Exception as e:  # noqa: BLE001
            return f"[error] not valid JSON/YAML: {e}"
    if not isinstance(doc, dict):
        return "[error] unrecognized document (expected an object)."
    eps = []
    if "swagger" in doc or "openapi" in doc:
        kind = "OpenAPI/Swagger"
        base = doc.get("basePath") or ""
        if not base and isinstance(doc.get("servers"), list) and doc["servers"]:
            base = (doc["servers"][0] or {}).get("url", "") if isinstance(doc["servers"][0], dict) else ""
        for path, methods in (doc.get("paths") or {}).items():
            if not isinstance(methods, dict):
                continue
            for mth, op in methods.items():
                if mth.lower() not in ("get", "post", "put", "patch", "delete", "head", "options"):
                    continue
                op = op or {}
                params = ",".join(p.get("name", "?") for p in (op.get("parameters") or []) if isinstance(p, dict))
                sec = "auth" if (op.get("security") or doc.get("security")) else "PUBLIC?"
                eps.append((mth.upper(), str(base) + str(path), params, sec, str(op.get("summary") or "")[:60]))
    elif "item" in doc or "postman" in str((doc.get("info") or {}).get("schema", "")).lower():
        kind = "Postman collection"

        def walk(items):
            for it in items or []:
                if isinstance(it, dict) and "item" in it:
                    walk(it["item"])
                elif isinstance(it, dict) and "request" in it:
                    req = it["request"]
                    if isinstance(req, str):
                        eps.append(("GET", req, "", "", str(it.get("name", ""))[:60]))
                        continue
                    u = req.get("url")
                    raw = u.get("raw") if isinstance(u, dict) else u
                    auth = "auth" if req.get("auth") or doc.get("auth") else ""
                    eps.append(((req.get("method") or "GET").upper(), str(raw or ""), "", auth,
                                str(it.get("name", ""))[:60]))
        walk(doc.get("item"))
    else:
        return "[error] not an OpenAPI/Swagger or Postman document."
    if not eps:
        return f"{kind}: no endpoints found."
    lines = [f"{kind}: {len(eps)} endpoints", ""]
    for mth, path, params, sec, summ in eps[:400]:
        lines.append(f"  {mth:6} {path}" + (f"  ?{params}" if params else "")
                     + (f"  [{sec}]" if sec else "") + (f"  - {summ}" if summ else ""))
    outp = os.path.join(_ws_dir() or "/tmp", f"api-inventory-{_ts()}.txt")
    try:
        with open(outp, "w", encoding="utf-8") as f:
            f.write("\n".join("\t".join(map(str, e)) for e in eps))
        lines.append(f"\n[saved inventory: {outp}]")
    except Exception:  # noqa: BLE001
        pass
    if len(eps) > 400:
        lines.append(f"... ({len(eps) - 400} more in the saved file)")
    return "\n".join(lines)


# ===========================================================================
#  ATTACK-SURFACE INTEL (Tier 2)
# ===========================================================================
@mcp.tool()
def js_analyze(source: str) -> str:
    """Extract API endpoints/routes and hardcoded secrets from JavaScript/HTML. source: a URL
    (fetched, scope-checked) or a /workspace file (or a directory of .js). Mines vendor bundles for
    hidden endpoints + leaked keys/tokens. Secrets are redacted."""
    texts = []
    if "://" in source:
        target, host, err = _guard(source)
        if err:
            return err
        text, err = _load_source_text(source)
        if err:
            return err
        texts.append((_display_http_url(source), text))
    else:
        try:
            p = _ws_path(source)
        except ValueError as e:
            return f"[error] {e}"
        files = []
        if os.path.isdir(p):
            for root, _d, fns in os.walk(p):
                for fn in fns:
                    if fn.lower().endswith((".js", ".html", ".json", ".map", ".ts")):
                        files.append(os.path.join(root, fn))
        elif os.path.isfile(p):
            files = [p]
        else:
            return f"[error] not found: {p}"
        for fp in files[:50]:
            try:
                with open(fp, encoding="utf-8", errors="replace") as f:
                    texts.append((fp, f.read()))
            except Exception:  # noqa: BLE001
                pass
    eps, secs = set(), []
    for _src, t in texts:
        eps.update(_find_endpoints(t))
        secs.extend(_find_secrets(t))
    eps = sorted(eps)
    out = [f"js_analyze: {len(texts)} source(s), {len(eps)} endpoints, {len(secs)} secret candidate(s)", ""]
    if secs:
        out.append("## secrets")
        seen = set()
        for s in secs:
            key = (s["type"], s["match"])
            if key not in seen:
                seen.add(key)
                out.append(f"  [{s['type']}] {s['match']}")
        out.append("")
    out.append("## endpoints")
    out += ["  " + e for e in eps[:300]]
    if len(eps) > 300:
        out.append(f"  ... ({len(eps) - 300} more)")
    return "\n".join(out)[:MAX_OUTPUT_CHARS]


@mcp.tool()
def secret_scan(source: str) -> str:
    """Scan a /workspace file, directory, or inline text for hardcoded secrets (API keys, tokens,
    private keys, JWTs). Reports type + redacted match + file:line."""
    hits = []

    def scan_file(fp):
        try:
            with open(fp, encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f, 1):
                    for s in _find_secrets(line):
                        hits.append(f"  {fp}:{i} [{s['type']}] {s['match']}")
        except Exception:  # noqa: BLE001
            pass

    looks_like_path = os.path.isabs(source) or "/" in source or "\\" in source
    if looks_like_path:
        try:
            p = _ws_path(source)
        except ValueError as e:
            return f"[error] {e}"
        if os.path.isdir(p):
            for root, _d, fns in os.walk(p):
                for fn in fns:
                    scan_file(os.path.join(root, fn))
        elif os.path.isfile(p):
            scan_file(p)
        else:
            return f"[error] not found in workspace: {source}"
    else:
        for s in _find_secrets(source):  # bare text (no path separators) -> scan inline
            hits.append(f"  [{s['type']}] {s['match']}")
    if not hits:
        return "No secrets found."
    return f"Secret scan: {len(hits)} match(es)\n" + "\n".join(hits[:200])


@mcp.tool()
def wayback_urls(domain: str) -> str:
    """Historical URL discovery for a domain via gau (Wayback/CommonCrawl/OTX) - surfaces forgotten
    endpoints, parameters and files. Scope-checked."""
    _, host, err = _guard(domain)
    return err or _run(["gau", "--subs", "--threads", "5", host], timeout=max(SCAN_TIMEOUT, 300))


@mcp.tool()
def uncover_search(query: str, engine: str = "shodan") -> str:
    """Passive host discovery via uncover (Shodan/Censys/Fofa/Quake/Hunter). Needs the matching API
    key in the image env/config; degrades with a clear message if absent. engine:
    shodan|censys|fofa|quake|hunter|netlas|zoomeye. Results are candidate hosts to then bring in
    scope. Not scope-checked (passive; sends no packets to the targets)."""
    try:
        q = _searchq(query)
    except ValueError as e:
        return f"[error] {e}"
    eng = engine if engine in ("shodan", "censys", "fofa", "quake", "hunter", "netlas", "zoomeye") else "shodan"
    return _run(["uncover", "-q", q, "-e", eng, "-silent"], timeout=max(SCAN_TIMEOUT, 300))


# ===========================================================================
#  OUT-OF-BAND / BLIND DETECTION (Tier 3) - interactsh
# ===========================================================================
_OAST_RE = re.compile(r"[a-z0-9]{10,}\.oast\.(?:fun|pro|site|online|live|me)", re.I)
_oob_lock = threading.Lock()
_oob = {"proc": None, "domain": None, "log": None}


def _oob_reap(proc):
    """Terminate and reap an interactsh process so it doesn't linger as a zombie."""
    if not proc:
        return
    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:  # noqa: BLE001
                proc.kill()
                proc.wait(timeout=5)
    except Exception:  # noqa: BLE001
        pass


@mcp.tool()
def oob_start() -> str:
    """Start an out-of-band interaction listener (interactsh) for BLIND vuln detection - blind SSRF,
    blind XSS, blind SQLi, RCE/DNS callbacks, log4shell. Returns a unique payload domain; embed it in
    payloads, then call oob_poll to see which fired (with source IP + protocol)."""
    with _oob_lock:
        if _oob["proc"] and _oob["proc"].poll() is None and _oob["domain"]:
            return f"OOB listener already running. Payload domain: {_oob['domain']}"
        _oob_reap(_oob.get("proc"))  # clean up any dead/stale listener first
        d = _ws_dir("oob") or "/tmp"
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        logf = os.path.join(d, f"interactions-{stamp}.jsonl")
        startup = os.path.join(d, f"oob-startup-{stamp}.log")
        try:
            sf = open(startup, "w")
            proc = subprocess.Popen(["interactsh-client", "-json", "-o", logf, "-pi", "5"],
                                    stdout=sf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        except FileNotFoundError:
            return "[error] interactsh-client not installed in image."
        except Exception as e:  # noqa: BLE001
            return f"[error] {e}"
        finally:
            try:
                sf.close()  # the child keeps its own dup of the fd
            except Exception:  # noqa: BLE001
                pass
        domain, deadline = None, time.time() + 12
        while time.time() < deadline:
            time.sleep(0.6)
            try:
                with open(startup, encoding="utf-8", errors="replace") as f:
                    mt = _OAST_RE.search(f.read())
                if mt:
                    domain = mt.group(0)
                    break
            except Exception:  # noqa: BLE001
                pass
            if proc.poll() is not None:
                break
        if not domain:
            _oob_reap(proc)
            return ("[error] interactsh-client did not return a payload domain "
                    "(needs outbound 53/80/443 egress to the interactsh servers).")
        _oob.update(proc=proc, domain=domain, log=logf)
        return (f"OOB listener up. Payload domain: {domain}\n"
                f"Embed subdomains of it in payloads (e.g. http://{domain}/ , DNS lookups of x.{domain}), "
                f"then call oob_poll.")


@mcp.tool()
def oob_poll() -> str:
    """Show out-of-band interactions captured since oob_start (a DNS/HTTP/SMTP callback = confirmed
    blind vuln). Each hit shows protocol, source IP, and the unique subdomain that fired."""
    with _oob_lock:
        logp, domain = _oob.get("log"), _oob.get("domain")
    if not logp:
        return "OOB listener not started - call oob_start first."
    if not os.path.isfile(logp):
        return f"No interactions yet on {domain}."
    hits = []
    try:
        with open(logp, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    j = json.loads(line)
                    hits.append(f"  [{str(j.get('protocol', '?')).upper()}] "
                                f"{j.get('remote-address', '?')} -> "
                                f"{j.get('full-id') or j.get('unique-id', '?')}  {j.get('timestamp', '')}")
                except Exception:  # noqa: BLE001
                    pass
    except Exception as e:  # noqa: BLE001
        return f"[error] {e}"
    if not hits:
        return f"No interactions yet on {domain}."
    return f"OOB interactions on {domain} ({len(hits)}):\n" + "\n".join(hits[-50:])


@mcp.tool()
def oob_stop() -> str:
    """Stop the interactsh OOB listener."""
    with _oob_lock:
        _oob_reap(_oob.get("proc"))
        _oob.update(proc=None, domain=None)
    return "OOB listener stopped."


# ===========================================================================
#  RECON ORCHESTRATION (Tier 4)
# ===========================================================================
@mcp.tool()
def recon_sweep(domain: str, severity: str = "medium,high,critical", screenshots: bool = True) -> str:
    """One-shot recon pipeline over a domain: subfinder (passive subs) -> httpx (live probe) ->
    nuclei (vuln scan) + optional screenshots. Deduped, nuclei/screenshots run in parallel, returned
    as one summary. Only in-scope subdomains are probed; the base domain must be in the allowlist."""
    _, host, err = _guard(domain)
    if err:
        return err
    try:
        sev = _sanitize(severity)
    except ValueError as e:
        return f"[error] {e}"
    subs = _run(["subfinder", "-d", host, "-silent"], timeout=max(SCAN_TIMEOUT, 300))
    found = sorted({s.strip().lower() for s in subs.splitlines()
                    if s.strip() and "." in s and " " not in s.strip() and "[" not in s})
    ordered = [host] + [s for s in found if s != host]
    inscope = [s for s in ordered if _in_scope(s)[0]] or [host]
    listf = os.path.join("/tmp", f"sweep-{os.getpid()}-{_ts()}.txt")
    with open(listf, "w") as f:
        f.write("\n".join(inscope) + "\n")
    probe = _run(["httpx-toolkit", "-l", listf, "-silent", "-nc", "-status-code", "-title",
                  "-tech-detect", "-web-server"], timeout=max(SCAN_TIMEOUT, 300))
    live = sorted({ln.split()[0] for ln in probe.splitlines() if ln.strip().startswith("http")})
    livef = os.path.join("/tmp", f"sweep-live-{os.getpid()}-{_ts()}.txt")
    with open(livef, "w") as f:
        f.write("\n".join(live) + "\n")

    results = {}

    def run_nuclei():
        try:
            results["nuclei"] = (_run(["nuclei", "-l", livef, "-severity", sev, "-silent", "-nc"],
                                      timeout=max(SCAN_TIMEOUT, 900)) if live else "(no live hosts)")
        except Exception as e:  # noqa: BLE001
            results["nuclei"] = f"[error] nuclei failed: {e}"

    def run_shots():
        try:
            d = _ws_dir("screenshots")
            results["shots"] = (_run(["gowitness", "scan", "file", "-f", livef, "--screenshot-path", d,
                                      "--chrome-path", "/usr/bin/chromium", "--write-none"],
                                     timeout=max(SCAN_TIMEOUT, 300)) if (live and d) else "(no live hosts)")
        except Exception as e:  # noqa: BLE001
            results["shots"] = f"[error] screenshots failed: {e}"

    threads = [threading.Thread(target=run_nuclei)]
    if screenshots:
        threads.append(threading.Thread(target=run_shots))
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    for tmp in (listf, livef):
        try:
            os.remove(tmp)
        except Exception:  # noqa: BLE001
            pass

    out = [f"# recon_sweep: {host}",
           f"subdomains found: {len(found)} | in-scope probed: {len(inscope)} | live: {len(live)}",
           "", "## live hosts", probe.strip() or "(none)",
           "", "## nuclei findings", (results.get("nuclei") or "(skipped)").strip() or "(none)"]
    if screenshots:
        out += ["", f"## screenshots -> /workspace/screenshots ({(results.get('shots') or '(skipped)').strip()[:200]})"]
    return "\n".join(out)[:MAX_OUTPUT_CHARS]


# ===========================================================================
#  HACKERONE REPORTING + CVSS (Tier 5)
# ===========================================================================
@mcp.tool()
def cvss_score(vector: str) -> str:
    """Compute a CVSS v3.1 base score + severity from a vector string, e.g.
    'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N'."""
    try:
        score, sev = _cvss31_base(vector)
    except Exception as e:  # noqa: BLE001
        return f"[error] invalid CVSS vector: {e}"
    return f"CVSS 3.1 base score: {score} ({sev})\nvector: {vector.strip()}"


@mcp.tool()
def generate_h1_report(title: str = "") -> str:
    """Generate a HackerOne-ready markdown report for a saved finding (matched by `title` substring,
    else the highest-severity finding): summary, CVSS, affected asset, numbered repro with the
    engagement attribution header, impact and remediation. Saved to /workspace."""
    d = _ws_dir()
    if not d:
        return "[error] /workspace not available."
    findings = []
    p = os.path.join(d, "findings.jsonl")
    if os.path.exists(p):
        for line in open(p, encoding="utf-8"):
            line = line.strip()
            if line:
                try:
                    findings.append(json.loads(line))
                except Exception:  # noqa: BLE001
                    pass
    if not findings:
        return "No findings recorded. Use save_finding first."
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    if title:
        cand = [f for f in findings if title.lower() in str(f.get("title", "")).lower()]
        if not cand:
            return f"No finding matching '{title}'."
        f = cand[0]
    else:
        f = sorted(findings, key=lambda r: order.get(str(r.get("severity", "")).lower(), 5))[0]
    sev = str(f.get("severity", "?")).upper()
    cvss = f.get("cvss", "")
    cvss_line = (f"{f.get('cvss_score', '')} ({f.get('cvss_severity', '')}) `{cvss}`"
                 if cvss else "_(not scored)_")
    attribution = "; ".join(f"{k}: {v}" for k, v in ATTRIBUTION.items()) or "(none configured)"
    impact = "See summary above." if f.get("detail") else "_—_"
    md = [f"# {f.get('title', '')}", "",
          f"**Severity:** {sev}  ", f"**CVSS:** {cvss_line}  ",
          f"**Weakness:** {f.get('cwe', '—')}  ",
          f"**Asset:** {f.get('target', '') or f.get('endpoint', '')}  ",
          f"**Reported:** {f.get('ts', '')}  ", "",
          "## Summary", "", f.get("detail", "") or "_—_", "",
          "## Steps to Reproduce", ""]
    if f.get("endpoint"):
        md += [f"Endpoint: `{f['endpoint']}`", ""]
    md += [f"Configured attribution header(s): `{attribution}`. Verify actual request evidence before submission.", ""]
    if f.get("request"):
        md += ["Request:", "```http", f["request"], "```", ""]
    if f.get("response"):
        md += ["Response:", "```http", f["response"], "```", ""]
    if f.get("evidence"):
        md += ["Evidence:", "```", f["evidence"], "```", ""]
    md += ["## Impact", "", impact, "", "## Remediation", "", f.get("remediation", "") or "_—_", "",
           "---", "_Generated by RED MCP. Authorized, in-scope, non-destructive testing only._"]
    slug = re.sub(r"[^a-z0-9]+", "-", str(f.get("title", "report")).lower()).strip("-")[:50]
    out = os.path.join(d, f"h1-{slug or 'report'}.md")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))
    return f"HackerOne report written to {out}\n\n" + "\n".join(md)[:4000]


if __name__ == "__main__":
    log.info("RED MCP up | %s | workspace=%s(writable=%s)",
             _scope_str(), WORKSPACE, _ws_available())
    mcp.run(transport="stdio")
