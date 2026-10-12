# SOCIS-AI-PT User Guide

Welcome to SOCIS-AI-PT, an AI-powered penetration testing and vulnerability management platform. This guide covers how to use the platform effectively.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Dashboard](#dashboard)
3. [Projects](#projects)
4. [Creating Scans](#creating-scans)
5. [Viewing Results](#viewing-results)
6. [Vulnerability Management](#vulnerability-management)
7. [Reports](#reports)
8. [AI Chat Assistant](#ai-chat-assistant)
9. [MITRE ATT&CK Browser](#mitre-attck-browser)
10. [Administration](#administration)
11. [AI Prompt Templates](#ai-prompt-templates)

---

## Getting Started

### Logging In

1. Navigate to the login page
2. You can login using:
   - **OpenID/OAuth**: Click "Sign in with Google" or "Sign in with Microsoft"
   - **Username/Password**: Enter your credentials

3. After successful login, you'll be redirected to the dashboard

### Dashboard Overview

The dashboard shows:
- **Stats**: Total projects, scans, vulnerabilities, and critical findings
- **Recent Scans**: Latest 10 scans with status and summary
- **Quick Actions**: Links to create new scans, access AI chat, and view reports
- **Platform Status**: Health of backend systems (API, Ollama, Redis)

---

## Dashboard

### Navigation

The left sidebar provides access to all major features:

- **Dashboard** - Overview and quick access
- **Projects** - Create and manage penetration test projects
- **Scans** - View all security scans and their results
- **Vulnerabilities** - Centralized vulnerability database
- **Reports** - Generate and download security reports
- **AI Chat** - Interact with AI security analyst
- **MITRE ATT&CK** - Browse the full ATT&CK knowledge base (techniques, groups, software, mitigations)
- **Admin** - System administration (admin only)

### Stats Cards

Each stat card shows:
- **Icon**: Identifying the metric
- **Number**: Current count
- **Change**: Increase/decrease indicator

Click any stat to filter the scan list by that status.

---

## Projects

### Creating a Project

1. Click **Projects** in the sidebar
2. Click **New Project** button
3. Fill in project details:
   - **Name**: Project identifier (e.g., "Customer A - Security Audit")
   - **Description**: Project goals and scope
   - **Scope**: IP ranges or domains to test (e.g., 192.168.0.0/16)

4. Click **Create Project**

### Project States

- **Active** - Currently being tested
- **Completed** - Testing finished
- **Archived** - Historical record, no changes
- **Paused** - Temporarily suspended

### Project Actions

**For each project, you can**:
- **Edit**: Update project details
- **Delete**: Remove project (WARNING: Deletes all scans)
- **New Scan**: Start a new penetration test

---

## Creating Scans

### Scanner Types

**Network Scan**
- Discovers hosts and open ports
- Detects services and versions
- Identifies network vulnerabilities
- Tools: Nmap, Nuclei

**Web Application Scan**
- Tests web server vulnerabilities
- Checks for OWASP Top 10
- Tests API security
- Tools: Nuclei, Burp Suite

**API Security Scan**
- Audits REST/GraphQL APIs
- Tests authentication/authorization
- Checks for injection vulnerabilities
- Tools: Burp Suite, Nuclei

**Cloud Infrastructure**
- Scans AWS, Azure, GCP resources
- Checks cloud security misconfigurations
- Verifies IAM policies
- Tools: CloudCheck, ScoutSuite

### Step 1: Basic Details

1. Click **Scans** → **New Scan**
2. Fill in:
   - **Project**: Select target project
   - **Scan Name**: Descriptive name
   - **Scan Type**: Choose from Network, Web, API, Cloud

3. Click **Next**

### Step 2: Target Configuration

**Single Target**:
```
https://example.com
or
192.168.1.100
```

**Multiple Targets**:
```
192.168.0.0/24
example.com
api.example.com
```

**Import Targets**:
Upload a file with one target per line.

### Step 3: Tool Selection

**Recommended Tools** (by scan type):
- **Network**: Nmap (host discovery), Nuclei (vulnerability scanning)
- **Web**: Nuclei (templates), Burp Scanner (manual validation)
- **API**: Nuclei (API templates), Postman (functional testing)
- **Cloud**: CloudCheck (misconfig), ScoutSuite (detailed audit)

**Custom Selection**:
- Check/uncheck individual tools
- Adjust tool parameters
- Set scan intensity

### Step 4: Scan Intensity

- **Quick** (15 min): Basic checks, high-priority templates
- **Standard** (1 hour): Comprehensive coverage, medium complexity
- **Aggressive** (4+ hours): Deep analysis, all templates, time-intensive

### Step 5: Scheduling

**Immediate**:
- Start scan now

**Scheduled**:
- Choose date and time
- Recurring scans (daily/weekly/monthly)

### Step 6: Review & Launch

Review all settings and click **Start Scan**.

---

## Viewing Results

### Scans List

The scans page shows all scans with:

| Column | Description |
|--------|-------------|
| **Name** | Scan identifier |
| **Status** | Current state (pending/running/completed) |
| **Progress** | Completion percentage |
| **Findings** | Count of vulnerabilities |
| **Critical** | High-severity findings |
| **Created** | When scan was initiated |
| **Actions** | Cancel, view details, delete |

**Filter Options**:
- **Status**: All, Pending, Running, Analyzing, Completed, Failed, Cancelled
- **Project**: Filter by project
- **Sort**: By name, date, or findings count

### Scan Details

Click on a scan to view detailed results:

#### Overview Tab

- **Scan Summary**
  - Target(s) scanned
  - Tools used
  - Duration
  - Completion time

- **Statistics**
  - Total vulnerabilities by severity
  - Vulnerabilities by type
  - Top affected components
  - Trend over time (if rescanned)

#### Tools Tab

Results from each scanning tool:

- **Tool Name** (e.g., Nmap)
- **Status** (Success, Partial, Failed)
- **Findings Count**
- **Key Results**
  - Hosts discovered
  - Ports found
  - Services identified
  - Issues detected

### Vulnerabilities Tab

Detailed list of findings:

| Info | Description |
|------|-------------|
| **Name** | Vulnerability type |
| **CVE** | CVE identifier (if applicable) |
| **Severity** | CVSS rating (Critical/High/Medium/Low) |
| **Component** | Affected service or application |
| **Status** | Open, Fixed, False Positive |

**Click a vulnerability** to expand details:
- Full description
- Proof of concept
- Remediation steps
- Related CVEs
- CVSS score and vector

### AI Analysis Tab

AI-generated analysis including:

- **Executive Summary**: High-level findings
- **Risk Assessment**: Impact analysis
- **Remediation Roadmap**: Prioritized fix recommendations
- **Threat Modeling**: Potential attack chains
- **Best Practices**: Security recommendations

### Live Updates

When a scan is running, the page updates in real-time:
- Progress percentage increases
- New findings appear
- Tool results stream in
- AI analysis generates insights

---

## Vulnerability Management

### Vulnerability Database

The **Vulnerabilities** page shows all findings across all scans:

**Search & Filter**:
- **Severity**: Critical, High, Medium, Low, Info
- **Status**: Open, Fixed, Resolved, False Positive
- **CVE ID**: Search by CVE number
- **Component**: Filter by affected service

### Vulnerability Details

Click a vulnerability to view:

**General Info**:
- Name and description
- CVE ID and CWE
- CVSS score and vector
- First/last seen dates

**Technical Details**:
- Affected component
- Proof of concept
- Evidence (screenshots, logs)
- Discovery method

**Remediation**:
- Step-by-step fix instructions
- Official vendor guidance
- Patch availability and version
- Configuration hardening tips

**History**:
- When originally discovered
- Status changes over time
- Actions taken

### Updating Vulnerability Status

1. Click the vulnerability
2. Update status:
   - **Open**: New/unreviewed
   - **Fixed**: Remediation applied
   - **Resolved**: Verified as fixed
   - **False Positive**: Not actually vulnerable

3. Add notes (optional)
4. Click **Save**

### CVE Information

For vulnerabilities with CVE IDs:

Click **CVE Details** to view:
- Published date
- CVSS v3 score
- References and advisories
- Affected software versions
- Available patches

---

## Reports

### Generating Reports

1. Click **Reports** in the sidebar
2. Click **Generate Report**
3. Select options:
   - **Scan**: Choose which scan to report on
   - **Format**: PDF, HTML, JSON, or CSV
   - **Options**:
     - ☑ Include remediation guidance
     - ☑ Include AI analysis
     - ☑ Executive summary
     - ☑ Detailed findings

4. Click **Generate**

### Report Formats

**PDF** (Professional)
- Formatted for printing
- Professional branding
- Executive summary
- Detailed tables and charts

**HTML** (Interactive)
- Browser viewable
- Interactive charts
- Sortable tables
- Search functionality

**JSON** (Data Export)
- Machine-readable format
- All raw data
- For integration with other tools

**CSV** (Spreadsheet)
- Excel/Sheets compatible
- Vulnerability list with details
- Easy to filter/sort

### Viewing Reports

Reports in progress show:
- Generation status
- Progress percentage
- Estimated time remaining

Completed reports can be:
- **Viewed**: In browser
- **Downloaded**: Save to computer
- **Emailed**: Send to stakeholders

---

## AI Chat Assistant

### Overview

The AI Chat is the platform's intelligence core. It goes beyond conversation — it **autonomously selects and executes live security tools** based on what you ask. Think of it as an AI security analyst with direct access to **22 integrated security tools**.

### Accessing AI Chat

1. Click **AI Chat** in the sidebar
2. Or use a quick action from the Dashboard

### Selecting a Provider and Model

Use the **Provider** and **Model** dropdowns at the top of the chat sidebar:

| Provider | Best For |
|----------|----------|
| **Ollama (external)** | Privacy — your own server, data stays on your network |
| **OpenAI** | Fastest responses, best reasoning |
| **Anthropic** | Deep analysis, long contexts |

Your selection is **saved to your account** — it persists across sessions and devices.

### How the Agentic AI Works

When you send a message, the AI runs a **two-pass pipeline**:

1. **Pass 1 (silent)** — The LLM reads your message and decides which tools to call. It emits internal tool-call tags.
2. **Tool dispatch** — The backend parses the tags and calls the MCP servers (in parallel where possible).
3. **Pass 2 (visible)** — The LLM receives the live tool data and streams a professional report back to you.

You'll see a progress block like:
```
🧠 SOCIS-AI — Analyzing request, querying live data sources...
> 🔎 CVE Lookup → CVE-2021-44228 (NVD · CISA KEV · EPSS · PoC Index)
✅ Live data retrieved from: CVE Database (NVD) · CISA KEV · EPSS · PoC Index
```

### What to Ask — Prompt Examples

**Exploit Research:**
```
Find exploits for CVE-2021-44228
  → Searches exploitdb_mcp for matching exploit entries

What exploits are available for Apache Struts on Linux?
  → Runs exploitdb_mcp.search_by_platform + search_exploits

Show me recent exploits from the last 30 days
  → Runs exploitdb_mcp.get_recent_exploits
```

**MITRE ATT&CK Threat Intelligence:**
```
What techniques does APT29 use?
  → Runs mitre_mcp.get_techniques_used_by_group

Show me all Initial Access techniques for Windows
  → Runs mitre_mcp.get_techniques_by_tactic + get_techniques_by_platform

How is T1190 mitigated?
  → Runs mitre_mcp.get_mitigations_for_technique

What software does Lazarus Group use?
  → Runs mitre_mcp.get_software_used_by_group
```

**WordPress & Web Auditing:**
```
Scan https://wordpress-site.com for vulnerabilities
  → Runs wpscan_mcp.wp_scan + nuclei_mcp.nuclei_scan

Enumerate WordPress users on https://target.com
  → Runs wpscan_mcp.wp_enum_users
```

**JWT & Authentication Testing:**
```
Decode this JWT: eyJhbGciOi...
  → Runs jwt_mcp.decode_jwt

Test if this JWT uses a weak secret
  → Runs jwt_mcp.test_weak_secret

Test alg=none vulnerability on this token
  → Runs jwt_mcp.test_alg_none
```

**CVE & Threat Intelligence:**
```
Tell me about CVE-2021-44228
  → Queries NVD, CISA KEV, EPSS, PoC Index simultaneously
  → Returns: severity, description, KEV status, exploitation probability, available exploits

Is CVE-2023-44487 actively exploited in the wild?
  → Checks CISA KEV catalog

What's the exploitation probability for CVE-2022-30190?
  → Returns EPSS score from FIRST.org

Are there public exploits for Log4Shell?
  → Searches Sploitus + GitHub + ExploitDB
```

**Network Scanning:**
```
Scan 192.168.1.100 for open ports
  → Runs nmap_scan with -sV flags

What services are running on 10.0.0.1?
  → Runs nmap_service_scan

Is port 22 open on 192.168.1.50?
  → Runs port_check
```

**Web Application Testing:**
```
Check https://example.com for common web vulnerabilities
  → Runs nuclei_scan + fingerprint_waf

What WAF is protecting https://target.com?
  → Runs waf_detection_mcp.fingerprint_waf

Find hidden directories on https://example.com
  → Runs ffuf_fuzz with common wordlist

Check the SSL certificate for github.com
  → Runs ssl_mcp.check_ssl
```

**OSINT & Reconnaissance:**
```
Do a whois lookup on example.com
  → Runs osint_mcp.whois_lookup

What DNS records does example.com have?
  → Runs osint_mcp.dns_lookup

Where is IP 8.8.8.8 located?
  → Runs osint_mcp.ip_geolocation
```

**Context-Aware Analysis:**
```
Analyze the nmap output above and list all vulnerabilities
  → AI reads prior messages in the conversation (last 20 turns)

Based on our earlier scan of 192.168.1.0/24, what should we target next?
  → Multi-turn awareness — AI remembers the conversation
```

### Session Management

The sidebar lists your past chat sessions. Each session:
- Has a title (auto-named from first message)
- Shows which provider/model was used
- Persists indefinitely in the database

Click a session to resume it — full conversation history loads.  
Click the trash icon to delete a session.  
Click **New Chat** to start fresh.

### Chat Shortcuts

| Action | Shortcut |
|--------|----------|
| Send message | Enter |
| New line | Shift+Enter |
| Quick prompts | Click the ⚡ suggestion chips |
| Help / tool list | Click the **?** icon |

---

## MITRE ATT&CK Browser

### Overview

The dedicated **MITRE ATT&CK** page (accessible from the sidebar) provides an interactive browser for the full ATT&CK knowledge base, powered by the `mitre_mcp` server running the ATT&CK v18 dataset.

### What You Can Browse

- **Tactics** — The 14 high-level adversary goals (Reconnaissance, Initial Access, Execution, Persistence, etc.)
- **Techniques & Sub-techniques** — Over 700 techniques with platform tags (Windows, Linux, macOS, Cloud, ICS, Mobile)
- **Groups (APTs)** — 130+ tracked threat actor groups with their TTPs
- **Software** — Malware and tools mapped to techniques
- **Mitigations** — Defensive controls mapped to techniques they address
- **Campaigns** — Named operations linked to groups and techniques
- **Data Sources** — Detection telemetry that detects specific techniques

### Domains

All three ATT&CK domains are supported:

| Domain | Scope |
|--------|-------|
| **Enterprise** | Windows, Linux, macOS, Cloud, Network, Containers |
| **Mobile** | Android and iOS adversary techniques |
| **ICS** | Industrial control systems and OT environments |

### Generating Navigator Layers

The MITRE page can generate **ATT&CK Navigator-compatible layer JSON** for any set of technique IDs. Import the exported JSON directly into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to visualize coverage.

---

## Administration

### Admin Panel (Admin Only)

Access at `/admin` or via sidebar if you're an administrator.

### User Management

#### Adding Users

1. Click **Users** tab
2. Click **Add User**
3. Enter details:
   - **Username**: Login identifier
   - **Email**: Contact email
   - **Password**: Initial password
   - **Role**: Admin, Analyst, Viewer, API User

4. Click **Create**

#### Role Descriptions

- **Admin**: Full access, manage users, configure system
- **Analyst**: Create/run scans, manage projects, view all reports
- **Viewer**: Read-only access to reports and findings
- **API User**: Programmatic access only

#### Managing Users

For each user:
- **Change Role**: Update access level
- **Disable**: Temporarily revoke access
- **Delete**: Permanently remove account

**Best Practice**: Use the principle of least privilege.

### LLM Configuration

#### Adding AI Providers

1. Click **LLM Configs** tab
2. Click **Add Provider**
3. Fill in:
   - **Name**: Display name
   - **Provider**: OpenAI, Anthropic, Ollama, etc.
   - **Model Name**: Model ID
   - **API Key**: Authentication (if required)
   - **Base URL**: Custom endpoint (if not default)

4. Click **Add Provider**

#### Testing Configuration

After adding a provider, the system automatically tests the connection.

### Audit Logs

View all system activity:
- Who performed actions
- What actions (create, delete, modify)
- When (timestamp)
- From where (IP address)

Use this for:
- Security auditing
- Compliance reporting
- Troubleshooting user issues

---

## AI Prompt Templates

Prompt templates define the **offensive methodology and role** the AI adopts when analyzing scan results. They are prepended to the base system prompt — so all MCP tool tags (`[SEARCH: CVE-...]`), workflow JSON rules, and tool invocation instructions are always preserved beneath them.

### Built-in Templates

Three templates are automatically seeded on every platform startup. No admin configuration is required:

| Template | Scan Type | Source |
|---|---|---|
| **Offensive Pentest Agent** | `full` | OWASP WSTG v4.2 — full 4-phase pentest methodology |
| **Bug Bounty Hunter** | `vuln_scan` | Senior bug bounty researcher — exploitability-first, report-ready output |
| **Recon & OSINT Agent** | `recon_only` | Passive-first attack surface mapping — Phase 0 + Phase 1 |

Built-in templates are marked with a 🔒 icon in the Admin UI and **cannot be deleted**.

### How Templates Are Applied

- When a scan runs, the worker checks for an **active default** template matching the scan's type (e.g. `full`, `vuln_scan`, `recon_only`).
- If found, the template is **prepended** to the base system prompt. The MCP tool instructions remain intact.
- If no template matches, the base system prompt is used as-is.
- AI Chat always uses the base system prompt directly — prompt templates do not affect chat sessions.

### Managing Templates (Admin Only)

Navigate to **Settings → Admin Control → Prompt Templates**.

#### Available Actions

| Action | Description |
|---|---|
| **Enable / Disable** | Toggle a template without deleting it |
| **Set Default** | Mark a template as the active one for its scan type (only one default per scan type) |
| **Edit** | Modify the system prompt text (allowed even for built-in templates) |
| **Delete** | Remove a custom template (blocked for built-in templates) |

#### Creating a Custom Template

Custom templates can be created via the Admin API:

```bash
curl -X POST https://your-platform/api/v1/admin/prompt-templates \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Custom Pentest Prompt",
    "scan_type": "full",
    "system_prompt": "You are an expert penetration tester...",
    "is_active": true,
    "is_default": true
  }'
```

Valid `scan_type` values: `full`, `quick`, `custom`, `recon_only`, `vuln_scan`, `workflow`. Set to `null` to apply as fallback for all scan types.

**Note:** Setting `is_default: true` automatically unsets the current default for the same scan type.

---

## Best Practices

### Scanning

- **Scope**: Always define clear scope before scanning
- **Timing**: Schedule scans during maintenance windows if possible
- **Frequency**: Weekly for active projects, monthly for baseline
- **Storage**: Archive old scans and reports for compliance

### Vulnerability Management

- **Prioritize**: Focus on critical findings first
- **Validate**: Confirm findings before spending effort on fixes
- **Document**: Record remediation steps and verification
- **Verify**: Re-scan after fixes to confirm resolution

### Reporting

- **Executive Summary**: Start with impact and trends
- **Technical Details**: Include CVSS scores and remediation effort
- **Timeline**: Provide realistic fix estimates
- **Follow-up**: Schedule review scans to verify remediation

### Security

- **Access Control**: Give users only needed permissions
- **Password**: Use strong, unique passwords (or SSO)
- **Secrets**: Never share API keys or credentials
- **Logs**: Monitor audit logs for suspicious activity

---

## Troubleshooting

### Scan Won't Start

**Check**:
- Targets are valid IP/domain
- Network connectivity to targets
- MCP servers are healthy (Check Admin → MCP Servers)
- Disk space is available

### Scan Hangs/Times Out

**Solutions**:
- Use "Quick" intensity first
- Reduce target scope
- Restart scanner service
- Check system resources (CPU, RAM, disk)

### AI Chat Not Responding

**Check**:
- LLM provider is configured (Admin → LLM Config)
- Provider is online (test connection)
- API key is valid
- Network connectivity to provider

### Can't Generate Report

**Verify**:
- Scan has completed
- User has proper permissions
- Disk space is available
- Report format is supported

---

## Support & Resources

- **Online Help**: https://docs.socis-ai-pt.com
- **Email**: support@socis-ai-pt.com
- **Chat Support**: Available in platform settings
- **Community**: https://forum.socis-ai-pt.com
- **GitHub Issues**: https://github.com/0x4hm3d/SOCIS-AI-PT/issues

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl/Cmd + K` | Command palette |
| `Ctrl/Cmd + /` | Help |
| `/` | Focus search |
| `G D` | Go to Dashboard |
| `G P` | Go to Projects |
| `G S` | Go to Scans |
| `G V` | Go to Vulnerabilities |
| `Esc` | Close modals/dialogs |

---

**Last Updated**: April 14, 2026  
**Version**: 1.0.0
