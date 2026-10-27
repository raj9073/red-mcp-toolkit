# ============================================================================
#  RED MCP - Kali full pentest toolkit for an MCP client (stdio).
#  AUTHORIZED PENETRATION TESTING ONLY -- see README.md.
# ============================================================================

# ---- Stage 1: build Go tools not packaged in Kali apt --------------------
FROM golang:latest AS gobuild
ENV CGO_ENABLED=0 GOBIN=/out
RUN mkdir -p /out
# Existing tools kept at @latest: older pinned tags fail to compile against the current
# Go toolchain (e.g. katana's tree-sitter dep), so @latest tracks the maintained release.
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install github.com/hahwul/dalfox/v2@latest
RUN go install github.com/ropnop/kerbrute@latest
# Tier 2/3 additions (pinned): historical URLs (gau), passive discovery (uncover), OOB (interactsh)
RUN go install github.com/lc/gau/v2/cmd/gau@v2.2.4
RUN go install github.com/projectdiscovery/uncover/cmd/uncover@v1.2.1
RUN go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@v1.3.1

# ---- Stage 2: the toolkit image ------------------------------------------
FROM kalilinux/kali-rolling:latest
ENV DEBIAN_FRONTEND=noninteractive \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    PYTHONUNBUFFERED=1 \
    CHROME_PATH=/usr/bin/chromium
WORKDIR /app

# Core runtime + host/port discovery
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip ca-certificates libcap2-bin curl wget whois \
        nmap masscan bind9-dnsutils exploitdb \
    && rm -rf /var/lib/apt/lists/*

# Web testing
RUN apt-get update && apt-get install -y --no-install-recommends \
        nikto dirb gobuster feroxbuster ffuf whatweb wafw00f nuclei wpscan sqlmap \
    && rm -rf /var/lib/apt/lists/*

# DNS / OSINT / modern web recon
RUN apt-get update && apt-get install -y --no-install-recommends \
        dnsenum dnsrecon sublist3r theharvester subfinder httpx-toolkit arjun \
    && rm -rf /var/lib/apt/lists/*

# SMB / SNMP / Active Directory
RUN apt-get update && apt-get install -y --no-install-recommends \
        enum4linux-ng smbclient smbmap nbtscan netexec snmp onesixtyone \
        impacket-scripts certipy-ad bloodhound.py ldap-utils \
    && rm -rf /var/lib/apt/lists/*

# TLS / auth / cracking / cred utils / exploitation
RUN apt-get update && apt-get install -y --no-install-recommends \
        sslscan testssl.sh hydra medusa john hashid cewl crunch commix \
    && rm -rf /var/lib/apt/lists/*

# Screenshots (gowitness + headless chromium)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gowitness chromium \
    && rm -rf /var/lib/apt/lists/*

# Wordlists (seclists is large -- the bulk of the image size)
RUN apt-get update && apt-get install -y --no-install-recommends \
        seclists wordlists \
    && rm -rf /var/lib/apt/lists/* \
    && gunzip -f /usr/share/wordlists/rockyou.txt.gz || true

# WinRM client + cloud/container/IaC auditing (Trivy)
RUN apt-get update && apt-get install -y --no-install-recommends \
        evil-winrm trivy \
    && rm -rf /var/lib/apt/lists/*

# Go-built tools (katana, dalfox, kerbrute)
COPY --from=gobuild /out/ /usr/local/bin/

# Raw-socket capability so nmap/masscan work as a non-root user
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap \
    && setcap cap_net_raw,cap_net_admin+eip /usr/bin/masscan || true

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt
COPY kali_security_server.py .

# Non-root user + persistent workspace mount point
RUN useradd -m -u 1000 -s /bin/bash mcpuser \
    && mkdir -p /workspace \
    && chown -R mcpuser:mcpuser /workspace /app
USER mcpuser

# Pre-fetch nuclei templates into the non-root user's home (non-fatal)
RUN nuclei -update-templates || true

ENTRYPOINT ["python3", "/app/kali_security_server.py"]
