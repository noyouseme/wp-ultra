#!/usr/bin/env python3
"""
WP-Ultra v2.0 — Advanced WordPress Security Scanner
Author  : Who C29?
GitHub  : https://github.com/noyouseme
Warning : For authorized penetration testing only.
"""

import argparse
import concurrent.futures
import json
import os
import sys
from datetime import datetime
from threading import Lock
from urllib.parse import urlparse

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from modules.fingerprinter import WPFingerprinter
from modules.vuln_scanner   import VulnerabilityScanner
from modules.exploiter       import Exploiter
from modules.bruter          import LoginBruter
from modules.reporter        import Reporter
from modules.utils import (
    banner, Logger, create_directory, normalize_url,
    print_info, print_success, print_error, print_warning, print_header,
    AUTHOR, VERSION, GITHUB,
)

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# ─────────────────────────────────────────────────────────────────────────────
class WPUltra:
    def __init__(self, args):
        self.args          = args
        self.target        = normalize_url(args.target)
        self.threads       = args.threads
        self.timeout       = args.timeout
        self.do_exploit    = args.exploit
        self.do_brute      = args.brute
        self.brute_user    = args.brute_user
        self.wordlist      = args.wordlist
        self.report_format = args.report_format
        self.verbose       = args.verbose

        # Output directory
        if args.output:
            self.output_dir = args.output
        else:
            domain    = urlparse(self.target).netloc.replace(":", "_")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_dir = f"results_{domain}_{timestamp}"
        create_directory(self.output_dir)

        self.logger = Logger(os.path.join(self.output_dir, "scan.log"))

        # HTTP session
        self.session = requests.Session()
        self.session.keep_alive = True
        if args.proxy:
            self.session.proxies = {"http": args.proxy, "https": args.proxy}

        ua = args.user_agent or DEFAULT_UA
        self.headers = {
            "User-Agent":                ua,
            "Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language":           "en-US,en;q=0.5",
            "Accept-Encoding":           "gzip, deflate",
            "Connection":                "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

        # Sub-modules
        self.fingerprinter = WPFingerprinter(
            self.session, self.target, self.headers,
            self.timeout, self.output_dir, self.threads,
        )
        self.vuln_scanner = VulnerabilityScanner(
            self.session, self.target, self.headers,
            self.timeout, self.threads, self.output_dir,
        )
        self.exploiter = Exploiter(
            self.session, self.target, self.headers,
            self.timeout, self.output_dir,
        )
        self.reporter = Reporter(self.output_dir, self.target)

    # ──────────────────────────────────────────────────────────────────────────
    def run(self, show_banner: bool = True) -> dict:
        if show_banner:
            banner()
        print_header(f"Scanning: {self.target}")
        self.logger.log(f"Scan started: {self.target}")

        wp_info      = {}
        vulns        = {}
        exploits     = {}
        brute_result = {}

        try:
            # Step 1 — Fingerprinting
            print_header("Phase 1 — Fingerprinting")
            wp_info = self.fingerprinter.fingerprint()
            if not wp_info.get("is_wordpress"):
                print_error("Target does not appear to be a WordPress site. Aborting.")
                return {}
            self._save_json("wp_info.json", wp_info)

            # Step 2 — Vulnerability Scanning
            print_header("Phase 2 — Vulnerability Scanning")
            vulns = self.vuln_scanner.scan(wp_info)
            self._save_json("vulnerabilities.json", vulns)

            # Step 3 — Exploitation (optional)
            if self.do_exploit:
                print_header("Phase 3 — Exploitation")
                vuln_list = self._flatten_vulns(vulns)
                exploits  = self.exploiter.exploit(vuln_list)
                self._save_json("exploitation.json", exploits)

            # Step 4 — Brute Force (optional)
            if self.do_brute:
                print_header("Phase 4 — Brute Force")
                usernames = self._resolve_brute_users(wp_info)
                bruter    = LoginBruter(
                    self.session, self.target, self.headers,
                    self.timeout, threads=self.threads,
                    wordlist_path=self.wordlist,
                )
                if wp_info.get("xmlrpc_enabled"):
                    brute_result["xmlrpc"] = bruter.brute_xmlrpc(usernames)
                brute_result["wp_login"] = bruter.brute_wp_login(usernames)
                self._save_json("brute_results.json", brute_result)

            # Step 5 — Reporting
            print_header("Phase 5 — Report Generation")
            self.reporter.print_console(wp_info, vulns, exploits)

            if self.report_format in ("html", "all"):
                self.reporter.generate_html_report(wp_info, vulns, exploits)
            if self.report_format in ("md", "all"):
                self.reporter.generate_markdown_report(wp_info, vulns, exploits)
            if self.report_format in ("json", "all"):
                self.reporter.generate_json_report(wp_info, vulns, exploits)

        except KeyboardInterrupt:
            print_warning("Scan interrupted by user.")
            self.logger.log("Scan interrupted by user.")
        except Exception as e:
            print_error(f"Unexpected error: {e}")
            self.logger.log(f"Error: {e}", "ERROR")
            if self.verbose:
                import traceback; traceback.print_exc()

        print_success(f"Results saved to: {self.output_dir}/")
        self.logger.log("Scan complete.")
        risk = self.reporter.calculate_risk(wp_info, vulns, exploits) if wp_info else {}
        return {"wp_info": wp_info, "vulns": vulns, "exploits": exploits, "risk": risk}

    # ──────────────────────────────────────────────────────────────────────────
    def _save_json(self, filename: str, data):
        path = os.path.join(self.output_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, default=str)
        if self.verbose:
            print_info(f"Saved: {path}")

    def _flatten_vulns(self, vulns: dict) -> list:
        flat = list(vulns.get("core", []))
        for slug, data in vulns.get("plugins", {}).items():
            for v in data.get("vulns", []):
                flat.append({**v, "plugin": slug})
        for slug, data in vulns.get("themes", {}).items():
            for v in data.get("vulns", []):
                flat.append({**v, "theme": slug})
        flat += vulns.get("sqli", [])
        flat += vulns.get("lfi",  [])
        return flat

    def _resolve_brute_users(self, wp_info: dict) -> list:
        if self.brute_user:
            return [u.strip() for u in self.brute_user.split(",")]
        users = [u.get("login") for u in wp_info.get("users", []) if u.get("login")]
        return users if users else ["admin"]


# ─────────────────────────────────────────────────────────────────────────────
class MassScanner:
    def __init__(self, args):
        self.args            = args
        self.targets_file    = args.targets_file
        self.mass_output_dir = args.mass_output_dir or "mass_scan_results"
        self.threads         = args.threads
        self.targets         = []
        self._lock           = Lock()
        self.summary         = []

    # ──────────────────────────────────────────────────────────────────────────
    def run(self):
        banner()
        if not os.path.isfile(self.targets_file):
            print_error(f"File not found: {self.targets_file}")
            sys.exit(1)

        with open(self.targets_file, "r", encoding="utf-8", errors="ignore") as f:
            self.targets = [l.strip() for l in f
                            if l.strip() and not l.startswith("#")]

        create_directory(self.mass_output_dir)
        print_info(f"Loaded {len(self.targets)} targets. Starting mass scan…")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(self._scan_one, enumerate(self.targets)))

        # Write summary
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        spath = os.path.join(self.mass_output_dir, f"summary_{ts}.json")
        with open(spath, "w", encoding="utf-8") as f:
            json.dump(self.summary, f, indent=4, default=str)

        ok  = sum(1 for s in self.summary if s.get("success"))
        print_success(f"\nMass scan complete: {ok}/{len(self.targets)} succeeded.")
        print_success(f"Summary → {spath}")

    # ──────────────────────────────────────────────────────────────────────────
    def _scan_one(self, idx_target):
        idx, target = idx_target
        print_info(f"[{idx+1}/{len(self.targets)}] {target}")

        args         = argparse.Namespace(**vars(self.args))
        args.target  = target
        domain       = urlparse(normalize_url(target)).netloc.replace(":", "_")
        args.output  = os.path.join(self.mass_output_dir, domain)

        try:
            scanner = WPUltra(args)
            result  = scanner.run(show_banner=False)
            risk    = result.get("risk", {})
            entry   = {"target": target, "success": True,
                       "output_dir": scanner.output_dir,
                       "risk_score": risk.get("score"),
                       "risk_band":  risk.get("band")}
        except Exception as e:
            entry = {"target": target, "success": False, "error": str(e)}

        with self._lock:
            self.summary.append(entry)


# ─────────────────────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wp_ultra.py",
        description=f"WP-Ultra v{VERSION} — Advanced WordPress Security Scanner | by {AUTHOR}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  python3 wp_ultra.py -t example.com
  python3 wp_ultra.py -t https://example.com --exploit --brute
  python3 wp_ultra.py -t example.com --brute --wordlist rockyou.txt
  python3 wp_ultra.py -t example.com --report-format all
  python3 wp_ultra.py -l targets.txt --threads 15

Author  : {AUTHOR}
GitHub  : {GITHUB}
        """,
    )

    # Target
    tg = p.add_mutually_exclusive_group(required=True)
    tg.add_argument("-t", "--target",       help="Single target URL or domain")
    tg.add_argument("-l", "--targets-file", dest="targets_file",
                    help="File with one target per line (mass scan)")

    # Output
    p.add_argument("-o", "--output",         help="Output directory (default: auto)")
    p.add_argument("--mass-output-dir",      dest="mass_output_dir",
                   default="mass_scan_results",
                   help="Base dir for mass scan results")
    p.add_argument("--report-format",        dest="report_format",
                   choices=["console","html","md","json","all"],
                   default="console",
                   help="Report format (default: console)")

    # Performance
    p.add_argument("--threads",  type=int, default=10,
                   help="Thread count (default: 10)")
    p.add_argument("--timeout",  type=int, default=20,
                   help="Request timeout in seconds (default: 20)")

    # Modules
    p.add_argument("--exploit",  action="store_true",
                   help="Attempt to exploit found vulnerabilities")
    p.add_argument("--brute",    action="store_true",
                   help="Brute force login (wp-login + XML-RPC)")
    p.add_argument("--brute-user", dest="brute_user",
                   help="Username(s) to brute (comma-separated, default: auto-detect)")
    p.add_argument("--wordlist", help="Custom password wordlist file")

    # Network
    p.add_argument("--proxy",       help="Proxy URL (e.g., http://127.0.0.1:8080)")
    p.add_argument("--user-agent",  dest="user_agent",
                   help="Custom User-Agent string")

    # Misc
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    p.add_argument("--version",  action="version",
                   version=f"WP-Ultra v{VERSION} by {AUTHOR} | {GITHUB}")

    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if args.targets_file:
        MassScanner(args).run()
    else:
        WPUltra(args).run()


if __name__ == "__main__":
    main()
