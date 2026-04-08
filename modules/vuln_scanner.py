#!/usr/bin/env python3
"""
WP-Ultra v2.0 — Vulnerability Scanner Module
Author  : Who C29?
CVE matching, SQLi, XSS, LFI, backup/config exposure, misconfiguration checks.
"""

import os
import re
import json
import concurrent.futures
from urllib.parse import urljoin, quote

from .utils import (safe_request, print_info, print_success, print_warning,
                    print_vuln, print_error, version_compare,
                    C, G, Y, R, W, M, RESET)

# ─── SQLi Payloads (quick detection) ─────────────────────────────────────────
SQLI_PAYLOADS = [
    "'", "\"", "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1",
    "1 AND 1=1", "1 AND 1=2", "' AND SLEEP(3)--",
    "1; SELECT SLEEP(3)", "' UNION SELECT NULL--",
]

# ─── XSS Payloads ─────────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
]

# ─── LFI Payloads ─────────────────────────────────────────────────────────────
LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../windows/win.ini",
    "../../../../etc/passwd%00",
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
]

# ─── SSRF Payloads ────────────────────────────────────────────────────────────
SSRF_TARGETS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/",
    "http://0.0.0.0/",
]

# ─── Exposed backup/config paths ─────────────────────────────────────────────
SENSITIVE_PATHS = [
    "/wp-config.php.bak",
    "/wp-config.php~",
    "/wp-config.php.old",
    "/wp-config.php.orig",
    "/wp-config.php_bak",
    "/wp-config.php.save",
    "/.env",
    "/.env.bak",
    "/.env.old",
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/backup.zip",
    "/backup.tar.gz",
    "/backup.tar",
    "/site.zip",
    "/site.tar.gz",
    "/wordpress.zip",
    "/db.sql",
    "/dump.sql",
    "/database.sql",
    "/backup.sql",
    "/wp-content/debug.log",
    "/wp-content/uploads/debug.log",
    "/error_log",
    "/php_error.log",
    "/wp-admin/install.php",
    "/wp-admin/setup-config.php",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/php.php",
    "/server-status",
    "/server-info",
    "/wp-includes/version.php",
]

# ─── Directory listing indicators ─────────────────────────────────────────────
DIR_LISTING_PATHS = [
    "/wp-content/uploads/",
    "/wp-content/plugins/",
    "/wp-content/themes/",
    "/wp-includes/",
]


class VulnerabilityScanner:
    def __init__(self, session, target, headers, timeout, threads, output_dir):
        self.session    = session
        self.target     = target
        self.headers    = headers
        self.timeout    = timeout
        self.threads    = threads
        self.output_dir = output_dir
        self.vulndb     = self._load_vulndb()

    def _load_vulndb(self) -> dict:
        db_path = os.path.join(os.path.dirname(__file__), "..", "data", "vulndb.json")
        try:
            with open(db_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print_warning(f"Could not load vulndb.json: {e}")
            return {"core": [], "plugins": {}, "themes": {}}

    # ──────────────────────────────────────────────────────────────────────────
    def scan(self, wp_info: dict) -> dict:
        results = {
            "core":              [],
            "plugins":           {},
            "themes":            {},
            "sqli":              [],
            "xss":               [],
            "lfi":               [],
            "ssrf":              [],
            "exposed_files":     [],
            "directory_listing": [],
            "misconfigurations": [],
        }

        version  = wp_info.get("version")
        plugins  = wp_info.get("plugins", {})
        themes   = wp_info.get("themes", [])

        # 1. Core CVE matching
        if version:
            print_info(f"Checking core CVEs for WordPress {version}…")
            results["core"] = self._check_core_cves(version)
            for v in results["core"]:
                print_vuln(f"[CORE] {v['id']} — {v['title']} (CVSS: {v.get('cvss','?')})")

        # 2. Plugin CVE matching
        print_info("Checking plugin CVEs…")
        for slug, pdata in plugins.items():
            pver = pdata.get("version")
            matches = self._check_plugin_cves(slug, pver)
            if matches:
                results["plugins"][slug] = {"version": pver, "vulns": matches}
                for v in matches:
                    print_vuln(f"[PLUGIN:{slug}] {v['id']} — {v['title']} (CVSS: {v.get('cvss','?')})")

        # 3. Theme CVE matching
        for theme in themes:
            slug = theme.get("name", "")
            tver = theme.get("version")
            matches = self._check_theme_cves(slug, tver)
            if matches:
                results["themes"][slug] = {"version": tver, "vulns": matches}
                for v in matches:
                    print_vuln(f"[THEME:{slug}] {v['id']} — {v['title']} (CVSS: {v.get('cvss','?')})")

        # 4. Exposed sensitive files
        print_info("Scanning for exposed sensitive files…")
        results["exposed_files"] = self._check_exposed_files()

        # 5. Directory listing
        results["directory_listing"] = self._check_directory_listing()

        # 6. SQLi testing
        print_info("Testing for SQL injection…")
        results["sqli"] = self._test_sqli()

        # 7. XSS testing
        print_info("Testing for XSS…")
        results["xss"] = self._test_xss()

        # 8. LFI testing
        print_info("Testing for LFI…")
        results["lfi"] = self._test_lfi()

        # 9. Misconfiguration checks
        results["misconfigurations"] = self._check_misconfigurations(wp_info)

        return results

    # ──────────────────────────────────────────────────────────────────────────
    # CVE MATCHING
    # ──────────────────────────────────────────────────────────────────────────
    def _check_core_cves(self, version: str) -> list:
        found = []
        for vuln in self.vulndb.get("core", []):
            fixed_in = vuln.get("fixed_in")
            if fixed_in and version_compare(version, fixed_in):
                found.append(vuln)
        return found

    def _check_plugin_cves(self, slug: str, version) -> list:
        found = []
        vulns = self.vulndb.get("plugins", {}).get(slug, [])
        for vuln in vulns:
            fixed_in = vuln.get("fixed_in")
            if not version:
                found.append({**vuln, "note": "version unknown — may be vulnerable"})
            elif fixed_in and version_compare(version, fixed_in):
                found.append(vuln)
        return found

    def _check_theme_cves(self, slug: str, version) -> list:
        found = []
        vulns = self.vulndb.get("themes", {}).get(slug, [])
        for vuln in vulns:
            fixed_in = vuln.get("fixed_in")
            if not version:
                found.append({**vuln, "note": "version unknown — may be vulnerable"})
            elif fixed_in and version_compare(version, fixed_in):
                found.append(vuln)
        return found

    # ──────────────────────────────────────────────────────────────────────────
    # EXPOSED FILES
    # ──────────────────────────────────────────────────────────────────────────
    # Content signatures to validate each exposed path (reduces false positives)
    _FILE_SIGNATURES = {
        "/wp-config.php": ["DB_NAME", "DB_USER", "DB_PASSWORD", "table_prefix"],
        "/.env":          ["APP_KEY", "DB_HOST", "DB_DATABASE", "SECRET", "="],
        "/.git/config":   ["[core]", "[remote", "repositoryformatversion"],
        "/.git/HEAD":     ["ref:", "refs/heads"],
        "/.svn/entries":  ["svn", "wc-entries"],
        "/wp-content/debug.log": ["PHP", "Notice", "Warning", "Error", "Stack"],
        "/phpinfo.php":   ["PHP Version", "phpinfo()", "php.ini"],
        "/info.php":      ["PHP Version", "phpinfo()"],
        "/server-status": ["Apache Server Status", "requests currently"],
        "/backup":        [],  # any content = suspicious
        "/dump.sql":      ["INSERT INTO", "CREATE TABLE", "--"],
        "/database.sql":  ["INSERT INTO", "CREATE TABLE", "--"],
        "/db.sql":        ["INSERT INTO", "CREATE TABLE", "--"],
    }

    def _validate_exposed(self, path: str, content: str) -> bool:
        """Return True only if the content looks like the real expected file."""
        # WordPress pages often return 200 with full HTML for 404s — skip those
        if "<html" in content.lower() and "<!doctype" in content.lower():
            # Allow only if it's a known HTML-format file
            if path not in ("/phpinfo.php", "/info.php", "/server-status"):
                return False
        # Check path-specific signatures
        for key, sigs in self._FILE_SIGNATURES.items():
            if key in path:
                if not sigs:
                    return True
                return any(s in content for s in sigs)
        # For archives/zips: just being present (200) is enough
        if any(path.endswith(ext) for ext in (".zip", ".tar.gz", ".tar", ".sql", ".bak", ".old", ".save", ".orig", "~")):
            return len(content) > 100
        return True

    def _check_exposed_files(self) -> list:
        found = []
        def probe(path):
            url = urljoin(self.target, path)
            r = safe_request(self.session, url, headers=self.headers,
                             timeout=self.timeout)
            if r and r.status_code == 200 and len(r.content) > 0:
                snippet = r.text[:300]
                if self._validate_exposed(path, snippet):
                    return {"path": path, "url": url, "size": len(r.content),
                            "snippet": snippet.replace("\n", " ")}
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            for res in ex.map(probe, SENSITIVE_PATHS):
                if res:
                    found.append(res)
                    print_vuln(f"Exposed file: {res['url']} ({res['size']} bytes)")
        return found

    # ──────────────────────────────────────────────────────────────────────────
    # DIRECTORY LISTING
    # ──────────────────────────────────────────────────────────────────────────
    def _check_directory_listing(self) -> list:
        found = []
        for path in DIR_LISTING_PATHS:
            url = urljoin(self.target, path)
            r = safe_request(self.session, url, headers=self.headers,
                             timeout=self.timeout)
            if r and r.status_code == 200:
                if "index of" in r.text.lower() or "parent directory" in r.text.lower():
                    found.append({"path": path, "url": url})
                    print_vuln(f"Directory listing enabled: {url}")
        return found

    # ──────────────────────────────────────────────────────────────────────────
    # SQL INJECTION
    # ──────────────────────────────────────────────────────────────────────────
    def _test_sqli(self) -> list:
        found = []
        # Test search form
        search_url = f"{self.target}/?s="
        error_signs = [
            "sql syntax", "mysql_fetch", "ora-01756", "pg_query",
            "sqlite_query", "you have an error in your sql",
            "unclosed quotation mark", "quoted string not properly terminated",
            "syntax error", "mysql error", "database error",
        ]
        for payload in SQLI_PAYLOADS[:5]:  # limit to first 5 for speed
            url = search_url + quote(payload)
            r = safe_request(self.session, url, headers=self.headers,
                             timeout=self.timeout)
            if r:
                body = r.text.lower()
                for sign in error_signs:
                    if sign in body:
                        result = {"url": url, "payload": payload,
                                  "indicator": sign, "type": "error-based"}
                        found.append(result)
                        print_vuln(f"Potential SQLi: {url} — indicator: '{sign}'")
                        break

        # Test comment form
        comment_url = urljoin(self.target, "/?p=1")
        for payload in SQLI_PAYLOADS[:3]:
            data = {
                "comment": payload,
                "author": "test",
                "email": "test@test.com",
                "url": "",
                "submit": "Post Comment",
            }
            r = safe_request(self.session, comment_url, method="POST",
                             headers=self.headers, data=data, timeout=self.timeout)
            if r:
                body = r.text.lower()
                for sign in error_signs:
                    if sign in body:
                        found.append({"url": comment_url, "payload": payload,
                                      "indicator": sign, "type": "error-based-comment"})
                        print_vuln(f"Potential SQLi in comment form: '{sign}'")
                        break

        return found

    # ──────────────────────────────────────────────────────────────────────────
    # XSS
    # ──────────────────────────────────────────────────────────────────────────
    def _test_xss(self) -> list:
        found = []
        search_url = f"{self.target}/?s="
        for payload in XSS_PAYLOADS[:4]:
            url = search_url + quote(payload)
            r = safe_request(self.session, url, headers=self.headers,
                             timeout=self.timeout)
            if r and payload in r.text:
                found.append({"url": url, "payload": payload,
                              "type": "reflected-xss"})
                print_vuln(f"Reflected XSS: {url}")
        return found

    # ──────────────────────────────────────────────────────────────────────────
    # LFI
    # ──────────────────────────────────────────────────────────────────────────
    def _test_lfi(self) -> list:
        found = []
        lfi_indicators = ["root:x:", "[boot loader]", "[operating systems]",
                          "[extensions]", "for 16-bit app"]
        # Test common LFI parameters
        params = ["file", "page", "include", "path", "template", "lang",
                  "dir", "view", "load", "document", "folder"]
        for param in params[:5]:
            for payload in LFI_PAYLOADS[:3]:
                url = f"{self.target}/?{param}={payload}"
                r = safe_request(self.session, url, headers=self.headers,
                                 timeout=self.timeout)
                if r:
                    for ind in lfi_indicators:
                        if ind in r.text:
                            found.append({"url": url, "param": param,
                                          "payload": payload, "indicator": ind})
                            print_vuln(f"LFI detected: {url} — '{ind}'")
                            break
        return found

    # ──────────────────────────────────────────────────────────────────────────
    # MISCONFIGURATIONS
    # ──────────────────────────────────────────────────────────────────────────
    def _check_misconfigurations(self, wp_info: dict) -> list:
        issues = []

        if wp_info.get("xmlrpc_enabled"):
            issues.append({
                "type": "XML-RPC Enabled",
                "severity": "MEDIUM",
                "description": "XML-RPC is enabled and can be abused for brute force (system.multicall), DDoS amplification, and user enumeration.",
                "recommendation": "Disable XML-RPC unless explicitly needed. Use a security plugin or add 'add_filter(\"xmlrpc_enabled\", \"__return_false\");' to functions.php.",
            })

        if wp_info.get("readme_exposed"):
            issues.append({
                "type": "Readme File Exposed",
                "severity": "LOW",
                "description": "readme.html exposes the WordPress version to unauthenticated users.",
                "recommendation": "Delete readme.html, readme.txt from the WordPress root.",
            })

        if wp_info.get("registration_open"):
            issues.append({
                "type": "User Registration Open",
                "severity": "MEDIUM",
                "description": "Public user registration is enabled. Attackers may register accounts to escalate privileges.",
                "recommendation": "Disable public registration in Settings > General unless required.",
            })

        if wp_info.get("debug_enabled"):
            issues.append({
                "type": "WP_DEBUG Enabled",
                "severity": "MEDIUM",
                "description": "PHP/WordPress debug output is visible in the response, exposing file paths and internal errors.",
                "recommendation": "Set WP_DEBUG to false in wp-config.php on production.",
            })

        sec_headers = wp_info.get("security_headers", {})
        missing_headers = [h for h, v in sec_headers.items() if v == "MISSING"
                           and h not in ("Server",)]
        if missing_headers:
            issues.append({
                "type": "Missing Security Headers",
                "severity": "LOW",
                "description": f"The following security headers are missing: {', '.join(missing_headers)}",
                "recommendation": "Add security headers via .htaccess or Nginx config.",
            })

        if wp_info.get("rest_api_enabled"):
            users = wp_info.get("users", [])
            if users:
                issues.append({
                    "type": "REST API User Enumeration",
                    "severity": "MEDIUM",
                    "description": f"The WP REST API exposes {len(users)} user(s) at /wp-json/wp/v2/users.",
                    "recommendation": "Restrict REST API access. Use a plugin like 'Disable REST API' or add authentication requirements.",
                })

        waf = wp_info.get("waf")
        if not waf:
            issues.append({
                "type": "No WAF Detected",
                "severity": "INFO",
                "description": "No Web Application Firewall signature was detected. The site may be unprotected from automated attacks.",
                "recommendation": "Consider using Cloudflare, Sucuri, or Wordfence as WAF.",
            })

        return issues
