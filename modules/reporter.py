#!/usr/bin/env python3
"""
WP-Ultra v2.0 — Reporter Module
Author  : Who C29?
Console summary, JSON, HTML (styled), and Markdown reports with risk scoring.
"""

import os
import json
from datetime import datetime

from .utils import (print_info, print_success, print_warning,
                    C, G, Y, R, M, W, B, RESET)

# ─── Risk scoring weights ─────────────────────────────────────────────────────
SEVERITY_SCORE = {
    "CRITICAL": 40,
    "HIGH":     20,
    "MEDIUM":   10,
    "LOW":       3,
    "INFO":      1,
}

CVSS_THRESHOLDS = {
    "CRITICAL": (9.0, 10.0),
    "HIGH":     (7.0,  8.9),
    "MEDIUM":   (4.0,  6.9),
    "LOW":      (0.1,  3.9),
}


def _severity_color(sev: str) -> str:
    return {"CRITICAL": R, "HIGH": Y, "MEDIUM": C, "LOW": G, "INFO": W}.get(sev.upper(), W)


def _html_severity_badge(sev: str) -> str:
    colors = {
        "CRITICAL": "#dc2626",
        "HIGH":     "#ea580c",
        "MEDIUM":   "#d97706",
        "LOW":      "#16a34a",
        "INFO":     "#6b7280",
    }
    bg = colors.get(sev.upper(), "#6b7280")
    return (f'<span style="background:{bg};color:#fff;'
            f'padding:2px 8px;border-radius:4px;font-size:12px;'
            f'font-weight:bold">{sev}</span>')


class Reporter:
    def __init__(self, output_dir: str, target: str):
        self.output_dir = output_dir
        self.target     = target
        self.timestamp  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ──────────────────────────────────────────────────────────────────────────
    # RISK SCORE
    # ──────────────────────────────────────────────────────────────────────────
    def calculate_risk(self, wp_info: dict, vulns: dict, exploits: dict) -> dict:
        score = 0
        breakdown = []

        def add(label, points, reason=""):
            nonlocal score
            score += points
            breakdown.append({"label": label, "points": points, "reason": reason})

        # Core CVEs
        for v in vulns.get("core", []):
            sev = v.get("severity", "MEDIUM")
            pts = SEVERITY_SCORE.get(sev, 5)
            add(f"Core CVE: {v.get('id')}", pts, sev)

        # Plugin CVEs
        for slug, data in vulns.get("plugins", {}).items():
            for v in data.get("vulns", []):
                sev = v.get("severity", "MEDIUM")
                pts = SEVERITY_SCORE.get(sev, 5)
                add(f"Plugin CVE [{slug}]: {v.get('id')}", pts, sev)

        # Theme CVEs
        for slug, data in vulns.get("themes", {}).items():
            for v in data.get("vulns", []):
                sev = v.get("severity", "MEDIUM")
                pts = SEVERITY_SCORE.get(sev, 5)
                add(f"Theme CVE [{slug}]: {v.get('id')}", pts, sev)

        # Active findings
        if vulns.get("sqli"):     add("SQL Injection", 25, "Active finding")
        if vulns.get("xss"):      add("XSS", 15, "Active finding")
        if vulns.get("lfi"):      add("LFI", 20, "Active finding")
        if vulns.get("ssrf"):     add("SSRF", 15, "Active finding")

        if vulns.get("exposed_files"):
            add("Exposed sensitive files", 10 * len(vulns["exposed_files"]),
                f"{len(vulns['exposed_files'])} file(s)")

        if vulns.get("directory_listing"):
            add("Directory Listing", 10, "")

        # Misconfigurations
        for mc in vulns.get("misconfigurations", []):
            pts = SEVERITY_SCORE.get(mc.get("severity", "LOW"), 3)
            add(f"Misconfig: {mc['type']}", pts, mc.get("severity", ""))

        # Exploitation success
        if exploits.get("default_creds"):
            add("Default Credentials Found", 50, "CRITICAL — admin access possible")
        if exploits.get("xmlrpc_bruteforce"):
            add("XML-RPC Brute Force Success", 45, "CRITICAL")
        if exploits.get("lfi_reads"):
            add("LFI Read Success", 30, "HIGH")

        # Risk band
        if score >= 100:
            band = "CRITICAL"
        elif score >= 60:
            band = "HIGH"
        elif score >= 30:
            band = "MEDIUM"
        elif score >= 10:
            band = "LOW"
        else:
            band = "INFO"

        return {"score": score, "band": band, "breakdown": breakdown}

    # ──────────────────────────────────────────────────────────────────────────
    # CONSOLE REPORT
    # ──────────────────────────────────────────────────────────────────────────
    def print_console(self, wp_info: dict, vulns: dict, exploits: dict):
        risk = self.calculate_risk(wp_info, vulns, exploits)
        sep  = f" {B}{'═'*62}{RESET}"

        print(f"\n{sep}")
        print(f" {W}  SCAN SUMMARY  —  {self.target}{RESET}")
        print(sep)

        # WP Info
        print(f"\n {C}WordPress Info{RESET}")
        print(f"   Version   : {W}{wp_info.get('version','Unknown')}{RESET}"
              + (f"  (sources: {', '.join(wp_info.get('version_sources', []))})"
                 if wp_info.get('version_sources') else ""))
        print(f"   WAF       : {wp_info.get('waf') or 'None detected'}")
        print(f"   XML-RPC   : {'Enabled' if wp_info.get('xmlrpc_enabled') else 'Disabled'}")
        print(f"   REST API  : {'Enabled' if wp_info.get('rest_api_enabled') else 'Disabled'}")
        print(f"   Users     : {len(wp_info.get('users', []))} found — "
              + ", ".join(u.get("login","?") for u in wp_info.get("users", [])[:5]))
        print(f"   Plugins   : {len(wp_info.get('plugins', {}))}")
        print(f"   Themes    : {len(wp_info.get('themes', []))}")

        # Vulnerabilities
        total_vulns = (len(vulns.get("core", [])) +
                       sum(len(d.get("vulns", [])) for d in vulns.get("plugins", {}).values()) +
                       sum(len(d.get("vulns", [])) for d in vulns.get("themes", {}).values()) +
                       len(vulns.get("sqli", [])) + len(vulns.get("xss", [])) +
                       len(vulns.get("lfi", [])) + len(vulns.get("exposed_files", [])))

        print(f"\n {R}Vulnerabilities ({total_vulns} total){RESET}")

        for v in vulns.get("core", []):
            sc = _severity_color(v.get("severity","?"))
            print(f"   {sc}[{v.get('severity','?')}]{RESET} {v.get('id')} — {v.get('title')}")

        for slug, data in vulns.get("plugins", {}).items():
            for v in data.get("vulns", []):
                sc = _severity_color(v.get("severity","?"))
                print(f"   {sc}[{v.get('severity','?')}]{RESET} [{slug}] {v.get('id')} — {v.get('title')}")

        for slug, data in vulns.get("themes", {}).items():
            for v in data.get("vulns", []):
                sc = _severity_color(v.get("severity","?"))
                print(f"   {sc}[{v.get('severity','?')}]{RESET} [theme:{slug}] {v.get('id')} — {v.get('title')}")

        for s in vulns.get("sqli", []):
            print(f"   {R}[HIGH]{RESET} SQLi — {s.get('url')} payload: {s.get('payload')}")
        for x in vulns.get("xss", []):
            print(f"   {Y}[MEDIUM]{RESET} XSS  — {x.get('url')}")
        for l in vulns.get("lfi", []):
            print(f"   {R}[HIGH]{RESET} LFI  — {l.get('url')}")
        for f in vulns.get("exposed_files", []):
            print(f"   {Y}[MEDIUM]{RESET} Exposed: {f.get('url')}")

        # Misconfigs
        if vulns.get("misconfigurations"):
            print(f"\n {Y}Misconfigurations{RESET}")
            for mc in vulns["misconfigurations"]:
                sc = _severity_color(mc.get("severity","LOW"))
                print(f"   {sc}[{mc.get('severity','?')}]{RESET} {mc.get('type')}")

        # Exploits
        if any(v for k, v in exploits.items() if v):
            print(f"\n {M}Exploitation Results{RESET}")
            for cred in exploits.get("default_creds", []):
                print(f"   {R}[CRITICAL]{RESET} Default creds: {cred['user']}:{cred['password']}")
            for cred in exploits.get("xmlrpc_bruteforce", []):
                print(f"   {R}[CRITICAL]{RESET} XML-RPC cred: {cred['user']}:{cred['password']}")
            for r in exploits.get("lfi_reads", []):
                print(f"   {R}[HIGH]{RESET}     LFI read: {r.get('file')} via {r.get('url')}")

        # Risk score
        rc = _severity_color(risk["band"])
        print(f"\n{sep}")
        print(f"   RISK SCORE : {rc}{risk['score']}{RESET}  [{rc}{risk['band']}{RESET}]")
        print(sep)
        print(f" {M}   WP-Ultra v2.0 — by Who C29?  |  github.com/noyouseme{RESET}")
        print(sep + "\n")

    # ──────────────────────────────────────────────────────────────────────────
    # JSON REPORT
    # ──────────────────────────────────────────────────────────────────────────
    def generate_json_report(self, wp_info, vulns, exploits) -> str:
        risk = self.calculate_risk(wp_info, vulns, exploits)
        data = {
            "meta":       {"target": self.target, "timestamp": self.timestamp, "tool": "WP-Ultra v2.0", "author": "Who C29?", "github": "https://github.com/noyouseme"},
            "risk":       risk,
            "wp_info":    wp_info,
            "vulns":      vulns,
            "exploits":   exploits,
        }
        path = os.path.join(self.output_dir, "report.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, default=str)
        print_success(f"JSON report saved → {path}")
        return path

    # ──────────────────────────────────────────────────────────────────────────
    # MARKDOWN REPORT
    # ──────────────────────────────────────────────────────────────────────────
    def generate_markdown_report(self, wp_info, vulns, exploits) -> str:
        risk  = self.calculate_risk(wp_info, vulns, exploits)
        lines = [
            f"# WP-Ultra Scan Report",
            f"",
            f"**Target:** {self.target}  ",
            f"**Date:**   {self.timestamp}  ",
            f"**Tool:**   WP-Ultra v2.0  ",
            f"**Author:** Who C29?  ",
            f"**GitHub:** https://github.com/noyouseme  ",
            f"",
            f"---",
            f"",
            f"## Risk Score: {risk['score']} — {risk['band']}",
            f"",
            f"## WordPress Info",
            f"",
            f"| Property | Value |",
            f"|---|---|",
            f"| Version | {wp_info.get('version','Unknown')} |",
            f"| WAF | {wp_info.get('waf') or 'None'} |",
            f"| XML-RPC | {'Enabled' if wp_info.get('xmlrpc_enabled') else 'Disabled'} |",
            f"| REST API | {'Enabled' if wp_info.get('rest_api_enabled') else 'Disabled'} |",
            f"| Users Found | {len(wp_info.get('users', []))} |",
            f"| Plugins | {len(wp_info.get('plugins', {}))} |",
            f"| Themes | {len(wp_info.get('themes', []))} |",
            f"",
            f"## Vulnerabilities",
            f"",
        ]

        def vuln_row(sev, title, cve="", note=""):
            return f"| {sev} | {cve} | {title} | {note} |"

        lines += ["| Severity | CVE | Title | Note |", "|---|---|---|---|"]
        for v in vulns.get("core", []):
            lines.append(vuln_row(v.get("severity","?"), v.get("title",""), v.get("id","")))
        for slug, data in vulns.get("plugins", {}).items():
            for v in data.get("vulns", []):
                lines.append(vuln_row(v.get("severity","?"), v.get("title",""),
                                      v.get("id",""), f"plugin: {slug}"))
        for slug, data in vulns.get("themes", {}).items():
            for v in data.get("vulns", []):
                lines.append(vuln_row(v.get("severity","?"), v.get("title",""),
                                      v.get("id",""), f"theme: {slug}"))
        for s in vulns.get("sqli", []):
            lines.append(vuln_row("HIGH", f"SQL Injection — {s.get('url')}", "Active"))
        for x in vulns.get("xss", []):
            lines.append(vuln_row("MEDIUM", f"XSS — {x.get('url')}", "Active"))
        for l in vulns.get("lfi", []):
            lines.append(vuln_row("HIGH", f"LFI — {l.get('url')}", "Active"))
        for f in vulns.get("exposed_files", []):
            lines.append(vuln_row("MEDIUM", f"Exposed file — {f.get('url')}", "Active"))

        lines += ["", "## Misconfigurations", ""]
        for mc in vulns.get("misconfigurations", []):
            lines += [f"### {mc.get('type')} [{mc.get('severity')}]",
                      f"{mc.get('description')}", "",
                      f"**Fix:** {mc.get('recommendation')}", ""]

        if any(v for k, v in exploits.items() if v):
            lines += ["## Exploitation Results", ""]
            for cred in exploits.get("default_creds", []) + exploits.get("xmlrpc_bruteforce", []):
                lines.append(f"- **[CRITICAL]** Valid credential: `{cred['user']}:{cred['password']}`")

        path = os.path.join(self.output_dir, "report.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print_success(f"Markdown report saved → {path}")
        return path

    # ──────────────────────────────────────────────────────────────────────────
    # HTML REPORT
    # ──────────────────────────────────────────────────────────────────────────
    def generate_html_report(self, wp_info, vulns, exploits) -> str:
        risk   = self.calculate_risk(wp_info, vulns, exploits)
        r_band = risk["band"]
        r_color = {"CRITICAL":"#dc2626","HIGH":"#ea580c","MEDIUM":"#d97706",
                   "LOW":"#16a34a","INFO":"#6b7280"}.get(r_band,"#6b7280")

        def trow(cells, header=False):
            tag = "th" if header else "td"
            return "<tr>" + "".join(f"<{tag}>{c}</{tag}>" for c in cells) + "</tr>"

        vuln_rows = ""
        for v in vulns.get("core", []):
            vuln_rows += trow([_html_severity_badge(v.get("severity","?")),
                               v.get("id",""), v.get("title",""), "WordPress Core", ""])
        for slug, data in vulns.get("plugins", {}).items():
            for v in data.get("vulns", []):
                vuln_rows += trow([_html_severity_badge(v.get("severity","?")),
                                   v.get("id",""), v.get("title",""),
                                   f"Plugin: {slug}",
                                   f"Fixed in {v.get('fixed_in','')}"])
        for slug, data in vulns.get("themes", {}).items():
            for v in data.get("vulns", []):
                vuln_rows += trow([_html_severity_badge(v.get("severity","?")),
                                   v.get("id",""), v.get("title",""),
                                   f"Theme: {slug}",
                                   f"Fixed in {v.get('fixed_in','')}"])
        for s in vulns.get("sqli", []):
            vuln_rows += trow([_html_severity_badge("HIGH"), "Active",
                               f"SQL Injection", s.get("url",""), s.get("payload","")])
        for x in vulns.get("xss", []):
            vuln_rows += trow([_html_severity_badge("MEDIUM"), "Active",
                               "Reflected XSS", x.get("url",""), ""])
        for l in vulns.get("lfi", []):
            vuln_rows += trow([_html_severity_badge("HIGH"), "Active",
                               "LFI", l.get("url",""), ""])
        for ef in vulns.get("exposed_files", []):
            vuln_rows += trow([_html_severity_badge("MEDIUM"), "Active",
                               "Exposed File", ef.get("url",""), ""])

        misc_html = ""
        for mc in vulns.get("misconfigurations", []):
            misc_html += f"""
            <div class="mc-card">
              <div class="mc-title">{_html_severity_badge(mc.get('severity','INFO'))}
                &nbsp;{mc.get('type','')}</div>
              <p>{mc.get('description','')}</p>
              <p><strong>Fix:</strong> {mc.get('recommendation','')}</p>
            </div>"""

        users_html = ""
        for u in wp_info.get("users", []):
            users_html += f"<li><code>{u.get('login','?')}</code> (ID:{u.get('id','?')}) — {u.get('source','')}</li>"

        exploit_html = ""
        for cred in exploits.get("default_creds", []) + exploits.get("xmlrpc_bruteforce", []):
            exploit_html += (f'<p style="color:#dc2626;font-weight:bold">'
                             f'[CRITICAL] Valid credential: {cred["user"]}:{cred["password"]} '
                             f'via {cred.get("method","")}</p>')

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WP-Ultra Report — {self.target}</title>
<style>
  :root {{--bg:#0f172a;--card:#1e293b;--border:#334155;--text:#e2e8f0;--accent:#38bdf8;}}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ background:var(--bg); color:var(--text); font-family:'Segoe UI',Arial,sans-serif; padding:24px; }}
  h1 {{ color:var(--accent); font-size:2rem; margin-bottom:4px; }}
  h2 {{ color:var(--accent); font-size:1.2rem; margin:24px 0 12px; border-left:4px solid var(--accent); padding-left:10px; }}
  .meta {{ color:#94a3b8; font-size:.9rem; margin-bottom:24px; }}
  .risk-badge {{ display:inline-block; padding:8px 20px; border-radius:8px;
                 font-size:1.5rem; font-weight:bold; color:#fff;
                 background:{r_color}; margin-bottom:24px; }}
  .card {{ background:var(--card); border:1px solid var(--border); border-radius:10px;
           padding:20px; margin-bottom:20px; }}
  table {{ width:100%; border-collapse:collapse; font-size:.9rem; }}
  th {{ background:#334155; padding:10px; text-align:left; color:var(--accent); }}
  td {{ padding:9px 10px; border-bottom:1px solid var(--border); vertical-align:top; }}
  tr:last-child td {{ border-bottom:none; }}
  code {{ background:#334155; padding:2px 6px; border-radius:4px; font-size:.85rem; }}
  .mc-card {{ background:#1e293b; border:1px solid #334155; border-radius:8px;
              padding:14px; margin-bottom:12px; }}
  .mc-title {{ margin-bottom:8px; font-weight:bold; }}
  ul {{ padding-left:20px; }}
  li {{ margin-bottom:6px; }}
  .grid {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; }}
  @media(max-width:700px) {{ .grid {{ grid-template-columns:1fr; }} }}
</style>
</head>
<body>
<h1>WP-Ultra — Security Scan Report</h1>
<div class="meta">Target: <strong>{self.target}</strong> &nbsp;|&nbsp; Date: {self.timestamp} &nbsp;|&nbsp; Tool: WP-Ultra v2.0</div>

<div class="risk-badge">Risk Score: {risk['score']} — {r_band}</div>

<div class="grid">
<div class="card">
  <h2>WordPress Information</h2>
  <table>
    <tr><td>Version</td><td><strong>{wp_info.get('version','Unknown')}</strong>
      {"<br><small>Sources: "+', '.join(wp_info.get('version_sources',[]))+"</small>" if wp_info.get('version_sources') else ""}</td></tr>
    <tr><td>WAF</td><td>{wp_info.get('waf') or '<span style="color:#ef4444">None detected</span>'}</td></tr>
    <tr><td>XML-RPC</td><td>{'<span style="color:#ef4444">Enabled</span>' if wp_info.get('xmlrpc_enabled') else 'Disabled'}</td></tr>
    <tr><td>REST API</td><td>{'<span style="color:#f59e0b">Enabled</span>' if wp_info.get('rest_api_enabled') else 'Disabled'}</td></tr>
    <tr><td>Plugins</td><td>{len(wp_info.get('plugins', {}))}</td></tr>
    <tr><td>Themes</td><td>{len(wp_info.get('themes', []))}</td></tr>
    <tr><td>Debug</td><td>{'<span style="color:#ef4444">Enabled</span>' if wp_info.get('debug_enabled') else 'Off'}</td></tr>
    <tr><td>Open Registration</td><td>{'<span style="color:#f59e0b">Yes</span>' if wp_info.get('registration_open') else 'No'}</td></tr>
  </table>
</div>
<div class="card">
  <h2>Detected Users ({len(wp_info.get('users',[]))})</h2>
  <ul>{users_html if users_html else '<li>None found</li>'}</ul>
</div>
</div>

<div class="card">
  <h2>Vulnerabilities</h2>
  {'<p style="color:#6b7280">No CVEs matched.</p>' if not vuln_rows else f"""
  <table>
    {trow(['Severity','CVE / ID','Title','Component','Note'], header=True)}
    {vuln_rows}
  </table>"""}
</div>

<div class="card">
  <h2>Misconfigurations</h2>
  {misc_html if misc_html else '<p style="color:#6b7280">No misconfigurations found.</p>'}
</div>

{f'<div class="card"><h2>Exploitation Results</h2>{exploit_html}</div>' if exploit_html else ''}

<div class="card">
  <h2>Risk Breakdown</h2>
  <table>
    {trow(['Finding','Points','Reason'], header=True)}
    {''.join(trow([b['label'], b['points'], b.get('reason','')]) for b in risk['breakdown'])}
    {trow([f'<strong>TOTAL</strong>', f'<strong>{risk["score"]}</strong>', f'<strong>{r_band}</strong>'])}
  </table>
</div>

<div class="card">
  <h2>Security Headers</h2>
  <table>
    {trow(['Header','Value'], header=True)}
    {''.join(trow([h, f'<span style="color:#ef4444">{v}</span>' if v == "MISSING" else f'<code>{v}</code>']) for h, v in wp_info.get('security_headers',{}).items())}
  </table>
</div>

<p style="color:#475569;font-size:.8rem;margin-top:24px;text-align:center">
  Generated by <strong style="color:#38bdf8">WP-Ultra v2.0</strong>
  &mdash; Created by <strong style="color:#a78bfa">Who C29?</strong>
  &mdash; <a href="https://github.com/noyouseme" style="color:#38bdf8">github.com/noyouseme</a>
  &mdash; For authorized security testing only
</p>
</body>
</html>"""

        path = os.path.join(self.output_dir, "report.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        print_success(f"HTML report saved → {path}")
        return path
