#!/usr/bin/env python3
"""
WP-Ultra v2.0 — Advanced WordPress Security Scanner
Author  : Who C29?
GitHub  : https://github.com/noyouseme
Warning : For authorized penetration testing only.
"""

import os
import re
import logging
from colorama import Fore, Style, init

init(autoreset=True)

# ─── Colors ───────────────────────────────────────────────────────────────────
R     = Fore.RED + Style.BRIGHT
G     = Fore.GREEN + Style.BRIGHT
Y     = Fore.YELLOW + Style.BRIGHT
B     = Fore.BLUE + Style.BRIGHT
C     = Fore.CYAN + Style.BRIGHT
M     = Fore.MAGENTA + Style.BRIGHT
W     = Fore.WHITE + Style.BRIGHT
DIM   = Style.DIM
RESET = Style.RESET_ALL

AUTHOR  = "Who C29?"
VERSION = "2.0"
GITHUB  = "https://github.com/noyouseme"

BANNER = f"""
{C}
 ██╗    ██╗██████╗       ██╗   ██╗██╗  ████████╗██████╗  █████╗
 ██║    ██║██╔══██╗      ██║   ██║██║  ╚══██╔══╝██╔══██╗██╔══██╗
 ██║ █╗ ██║██████╔╝█████╗██║   ██║██║     ██║   ██████╔╝███████║
 ██║███╗██║██╔═══╝ ╚════╝██║   ██║██║     ██║   ██╔══██╗██╔══██║
 ╚███╔███╔╝██║           ╚██████╔╝███████╗██║   ██║  ██║██║  ██║
  ╚══╝╚══╝ ╚═╝            ╚═════╝ ╚══════╝╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
{RESET}
 {M} {'─'*60}{RESET}
 {Y}[>] Advanced WordPress Security Scanner v{VERSION}{RESET}
 {G}[>] Author  : {W}{AUTHOR}{RESET}
 {G}[>] GitHub  : {W}{GITHUB}{RESET}
 {C}[>] Warning : Hanya untuk Authorized Penetration Testing{RESET}
 {M} {'─'*60}{RESET}
"""


def banner():
    print(BANNER)


class Logger:
    def __init__(self, log_file):
        self.log_file = log_file
        # Use a unique logger name per instance so mass scan writes to separate files
        self._logger = logging.getLogger(f'wp_ultra.{id(self)}')
        self._logger.setLevel(logging.DEBUG)
        self._logger.propagate = False
        # Remove old handlers if any (in case of reuse)
        self._logger.handlers.clear()
        handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
        handler.setFormatter(
            logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
        )
        self._logger.addHandler(handler)

    def log(self, message, level="INFO"):
        method = getattr(self._logger, level.lower(), self._logger.info)
        method(message)


def print_info(msg):    print(f" {C}[*]{RESET} {msg}")
def print_success(msg): print(f" {G}[+]{RESET} {msg}")
def print_error(msg):   print(f" {R}[-]{RESET} {msg}")
def print_warning(msg): print(f" {Y}[!]{RESET} {msg}")
def print_vuln(msg):    print(f" {R}[VULN]{RESET} {msg}")
def print_exploit(msg): print(f" {M}[PWN]{RESET}  {msg}")
def print_brute(msg):   print(f" {Y}[BRU]{RESET}  {msg}")


def print_header(title):
    w = 60
    print(f"\n {B}╔{'═'*w}╗{RESET}")
    print(f" {B}║{RESET} {W}{title.center(w)}{RESET} {B}║{RESET}")
    print(f" {B}╚{'═'*w}╝{RESET}\n")


def create_directory(path):
    os.makedirs(path, exist_ok=True)


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url.rstrip('/')


def safe_request(session, url, method='GET', timeout=30,
                 allow_redirects=True, **kwargs):
    """HTTP request wrapper with silent error handling."""
    try:
        fn = session.get if method.upper() == 'GET' else session.post
        return fn(url, timeout=timeout, verify=False,
                  allow_redirects=allow_redirects, **kwargs)
    except Exception:
        return None


def version_compare(version: str, fixed_in: str) -> bool:
    """Return True if version < fixed_in (i.e., still vulnerable)."""
    try:
        def parse(v):
            return tuple(int(x) for x in re.findall(r'\d+', str(v)))
        return parse(version) < parse(fixed_in)
    except Exception:
        return False
