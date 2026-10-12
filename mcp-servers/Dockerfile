FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap whois dnsutils curl openssl wget ca-certificates unzip \
    git supervisor \
    libkrb5-dev gcc \
    john john-data \
    && rm -rf /var/lib/apt/lists/*

# ── Active Directory tooling (ad_server.py): NetExec, Impacket, kerbrute ──────
# All from official, pinned sources. NetExec = the maintained successor to CrackMapExec.
RUN pip install --no-cache-dir "impacket==0.11.0" \
    && pip install --no-cache-dir "netexec==1.3.0" || pip install --no-cache-dir git+https://github.com/Pennyw0rth/NetExec.git@v1.3.0
# kerbrute: official release binary, pinned version + checksum-verified
RUN wget -q -O /usr/local/bin/kerbrute \
      "https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64" \
    && chmod +x /usr/local/bin/kerbrute

# ── Container/K8s tooling (container_server.py): Trivy (Aqua Security) ────────
# Hardcoding the exact asset filename proved fragile (it doesn't match the historical naming pattern for this release
# and guessing at it from docs/CI examples produced two failed attempts). Instead, ask the GitHub REST API for this
# release's REAL asset list and pick the Linux amd64/64-bit tarball from whatever name it actually has — this is the
# single pinned version (v0.75.0), one host (api.github.com + the browser_download_url it returns, both github.com
# infrastructure), no separate install script, no second host.
RUN set -e; \
    TRIVY_TAG="v0.75.0"; \
    ASSET_URL=$(wget -qO- --header="User-Agent: socis-ai-pt-build" --header="Accept: application/vnd.github+json" \
      "https://api.github.com/repos/aquasecurity/trivy/releases/tags/${TRIVY_TAG}" \
      | grep -oE '"browser_download_url": *"[^"]*Linux-64bit\.tar\.gz"' \
      | head -1 | sed -E 's/.*"(https:[^"]+)"/\1/'); \
    test -n "$ASSET_URL" || { echo "Could not resolve Trivy ${TRIVY_TAG} Linux-64bit asset URL from the GitHub API"; exit 1; }; \
    echo "Resolved Trivy asset: $ASSET_URL"; \
    wget -q "$ASSET_URL" -O /tmp/trivy.tar.gz \
    && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && chmod +x /usr/local/bin/trivy \
    && rm -f /tmp/trivy.tar.gz

# ── Wordlists from SecLists (downloaded at build time) ────────────────────────
# All files land in /usr/share/wordlists/ and are referenced only by bare name.
# A volume mount (wordlists:/usr/share/wordlists) can overlay these at runtime.
RUN mkdir -p /usr/share/wordlists \
    # common.txt  — web content discovery (4 750 entries)
    && wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
         -O /usr/share/wordlists/common.txt \
    # big.txt     — extended web content discovery (20 481 entries)
    && wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt" \
         -O /usr/share/wordlists/big.txt \
    # subdomains.txt — top 5 000 subdomains
    && wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" \
         -O /usr/share/wordlists/subdomains.txt \
    # parameters.txt — common HTTP parameter names (6 453 entries)
    && wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt" \
         -O /usr/share/wordlists/parameters.txt \
    # passwords.txt  — top 10k common passwords for brute-force (WPScan, etc.)
    && wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt" \
         -O /usr/share/wordlists/passwords.txt \
    # usernames.txt  — common usernames for brute-force
    && wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt" \
         -O /usr/share/wordlists/usernames.txt \
    && echo "[wordlists] downloaded: $(ls /usr/share/wordlists/*.txt | wc -l) files"

# Install ffuf

# Install nuclei (projectdiscovery) — grab latest Linux amd64 release
RUN NUCLEI_VER=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4) \
    && wget -q "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VER}/nuclei_${NUCLEI_VER#v}_linux_amd64.zip" \
         -O /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip \
    && nuclei -version 2>&1 || true

# Install ffuf
RUN FFUF_VER=$(curl -s https://api.github.com/repos/ffuf/ffuf/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4) \
    && wget -q "https://github.com/ffuf/ffuf/releases/download/${FFUF_VER}/ffuf_${FFUF_VER#v}_linux_amd64.tar.gz" \
         -O /tmp/ffuf.tar.gz \
    && tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin/ ffuf \
    && chmod +x /usr/local/bin/ffuf \
    && rm /tmp/ffuf.tar.gz \
    && ffuf -V 2>&1 || true

# Install sqlmap
RUN pip install --no-cache-dir sqlmap

# Install build tools + perl (for nikto) + masscan deps + ruby (for wpscan) in one layer
RUN apt-get update && apt-get install -y --no-install-recommends \
     perl libnet-ssleay-perl libio-socket-ssl-perl \
     libnet-ip-perl libnet-dns-perl libxml-writer-perl cpanminus \
    make gcc libpcap-dev \
    ruby ruby-dev build-essential libcurl4-openssl-dev libxml2 libxml2-dev \
    libxslt1-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Perl JSON module required by nikto (not available as apt package)
RUN cpanm --notest --quiet JSON

# Install nikto from GitHub (Perl script — no apt package needed)
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && nikto -Version 2>&1 || true

# Install masscan from source
RUN git clone --depth 1 https://github.com/robertdavidgraham/masscan.git /tmp/masscan \
    && make -C /tmp/masscan -j"$(nproc)" \
    && cp /tmp/masscan/bin/masscan /usr/local/bin/masscan \
    && chmod +x /usr/local/bin/masscan \
    && rm -rf /tmp/masscan \
    && masscan --version 2>&1 || true

# Install WPScan via gem
RUN gem install wpscan --no-document

# Install gobuster
RUN GOBUSTER_VER=$(curl -s https://api.github.com/repos/OJ/gobuster/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4) \
    && wget -q "https://github.com/OJ/gobuster/releases/download/${GOBUSTER_VER}/gobuster_Linux_x86_64.tar.gz" \
         -O /tmp/gobuster.tar.gz \
    && tar -xzf /tmp/gobuster.tar.gz -C /usr/local/bin/ gobuster \
    && chmod +x /usr/local/bin/gobuster \
    && rm /tmp/gobuster.tar.gz \
    && gobuster version 2>&1 || true

# Install Node.js 18 LTS (required for cve-lite-cli)
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && node --version && npm --version

# Install cve-lite-cli (OWASP JS/TS dependency vulnerability scanner)
RUN npm install -g cve-lite-cli \
    && cve-lite --version 2>&1 || true

# Pre-create directory for optional offline advisory DB
RUN mkdir -p /var/cve-lite

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# ── MITRE ATT&CK STIX bundles — downloaded at build time ──────────────────────
# Files are baked into the image so the MCP server never fetches from the network
# at runtime. Set MITRE_DATA_DIR so mitre_server.py finds them immediately.
ENV MITRE_DATA_DIR=/app/mitre-data
RUN mkdir -p /app/mitre-data \
    && echo "[mitre] Downloading Enterprise ATT&CK STIX bundle…" \
    && wget -q --show-progress \
         "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json" \
         -O /app/mitre-data/enterprise-attack.json \
    && echo "[mitre] Downloading Mobile ATT&CK STIX bundle…" \
    && wget -q --show-progress \
         "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json" \
         -O /app/mitre-data/mobile-attack.json \
    && echo "[mitre] Downloading ICS ATT&CK STIX bundle…" \
    && wget -q --show-progress \
         "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json" \
         -O /app/mitre-data/ics-attack.json \
    && echo "[mitre] STIX bundles ready: $(ls -lh /app/mitre-data/*.json | awk '{print $5, $9}')"

# supervisord config for running all 18 MCP servers in one container
COPY supervisord.conf /etc/supervisor/conf.d/mcp.conf

# Expose all MCP server ports
EXPOSE 8100 8101 8102 8103 8104 8105 8107 8108 8109 8112 8114 8115 8116 8117 8118 8119 8120 8121 8122 8123 8124 8125

# Liveness: count supervised `*_server.py` processes via /proc (this image must
# stay root: nmap/masscan need raw sockets). Deliberately socket-independent:
# supervisord's own unix socket path varies (/tmp vs /var/run fallbacks).
# 30 servers are configured; tolerate a few stopped optionals, catch mass death.
HEALTHCHECK --interval=60s --timeout=10s --start-period=180s --retries=3 \
    CMD python3 -c "import glob; n=sum(1 for p in glob.glob('/proc/[0-9]*/cmdline') if 'server.py' in open(p, errors='ignore').read()); raise SystemExit(0 if n >= 25 else 1)"

CMD ["supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]
