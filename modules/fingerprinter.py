#!/usr/bin/env python3
"""
WP-Ultra v2.0 — Fingerprinting Module
Author  : Who C29?
Detects WP version (10+ methods), plugins, themes, users, WAF, and security config.
"""

import re
import json
import concurrent.futures
from typing import Optional, Tuple, List, Dict
from urllib.parse import urljoin, urlparse

from .utils import (safe_request, print_info, print_success,
                    print_warning, print_error, C, G, Y, R, W, M, RESET)

# ─── 500+ top WordPress plugins to actively probe ─────────────────────────────
TOP_PLUGINS = [
    "akismet","contact-form-7","woocommerce","elementor","yoast-seo",
    "jetpack","wp-super-cache","wpforms-lite","wordfence","all-in-one-seo-pack",
    "classic-editor","wp-optimize","really-simple-ssl","duplicate-post",
    "mailchimp-for-wp","wp-file-manager","litespeed-cache","updraftplus",
    "redirection","wp-smushit","beaver-builder-lite-version","divi",
    "advanced-custom-fields","the-events-calendar","buddypress","bbpress",
    "wp-mail-smtp","ninja-forms","tablepress","wp-fastest-cache","w3-total-cache",
    "autoptimize","amp","enable-media-replace","popup-maker","cookie-law-info",
    "wp-google-maps","loco-translate","formidable","user-registration",
    "dokan-lite","easy-digital-downloads","restrict-content-pro","memberpress",
    "socialsnap","sassy-social-share","addtoany","wp-mobile-menu","redis-cache",
    "google-analytics-for-wordpress","google-site-kit","monsterinsights",
    "facebook-for-woocommerce","facebook-pixel","pixelyoursite","cookie-notice",
    "complianz","gdpr-cookie-consent","disable-comments","code-snippets",
    "insert-headers-and-footers","advanced-ads","ad-inserter","adrotate",
    "svg-support","safe-svg","embedpress","live-chat-support","tawk-to-live-chat",
    "tidio-live-chat","crisp","hubspot","woo-gutenberg-products-block",
    "woocommerce-blocks","woocommerce-wishlists","woocommerce-subscriptions",
    "woocommerce-bookings","woocommerce-memberships","wp-job-manager",
    "learnpress","learndash","tutor","lifterlms","motopress-hotel-booking",
    "loginpress","limit-login-attempts-reloaded","two-factor",
    "google-authenticator","wp-2fa","disable-xmlrpc","perfmatters",
    "all-in-one-wp-security-and-firewall","ithemes-security","wp-cerber",
    "security-ninja","backup-buddy","backwpup","duplicator",
    "all-in-one-wp-migration","wp-reset","custom-post-type-ui","pods",
    "meta-box","health-check","query-monitor","debug-bar","wp-dbmanager",
    "revolution-slider","slider-revolution","master-slider","smart-slider-3",
    "soliloquy","metaslider","nextgen-gallery","envira-gallery",
    "photo-gallery","modula-best-grid-gallery","royal-elementor-addons",
    "happy-elementor-addons","essential-addons-for-elementor-lite","elementor-pro",
    "jet-elements","premium-addons-for-elementor","give","charitable",
    "rank-math","smush","polylang","translatepress-multilingual",
    "wpml","multi-currency-for-woocommerce","cartflows","funnel-builder",
    "optimizepress","thrive-architect","brizy","astra","oceanwp",
    "generatepress","neve","kadence-blocks","spectra","surecart","stripe",
    "woocommerce-gateway-stripe","woocommerce-paypal-payments",
    "paypal-for-woocommerce","wp-rocket","comet-cache","cache-enabler",
    "flying-pages","wp-mail-smtp","fluent-smtp","postman-smtp",
    "gravityforms","caldera-forms","everest-forms","fluentforms","forminator",
    "wp-review-pro","kk-star-ratings","rate-my-post",
    "wpvivid-backups","migration-backup","wp-clone",
    "child-theme-configurator","codemagic","safe-svg","svg-vector-icon-plugin",
    "wptouch","amp-for-wp","accelerated-mobile-pages","flying-scripts",
    "asset-cleanup","gonzales","swift-performance-lite","wp-rocket",
    "tablesorter","ninja-tables","wp-table-builder","tablesome",
    "revive-old-posts","post-expirator","ultimate-addons-for-gutenberg",
    "kadence-woocommerce-email-designer","wp-product-review-lite",
    "login-lockdown","loginizer","wp-ban","ip-geo-block","shield-security",
    "wordfence-login-security","bbpress","buddyboss-platform",
    "wc-vendors","multivendorx","dokan-lite","wcfm-marketplace",
    "product-vendors","woocommerce-product-addon","woocommerce-pdf-invoices",
    "yith-woocommerce-wishlist","yith-woocommerce-compare",
    "yith-woocommerce-quick-view","yith-woocommerce-ajax-navigation",
    "woocommerce-abandoned-cart","mailchimp-for-woocommerce",
    "klaviyo","drip-ecommerce-crm-for-woocommerce",
    "wp-liveChat-support","crisp","olark","drift","intercom",
    "chatbot","wp-chatbot","tidio","tawk","freshchat",
    "wplnst","wp-external-links","rel-nofollow-checkbox",
    "broken-link-checker","link-library","pretty-links",
    "amazon-auto-links","datafeedr-woocommerce-importer",
    "affiliate-wp","pretty-links","thirstyaffiliates",
    "wps-hide-login","rename-wp-login","change-wp-admin-login",
    "sf-move-login","admin-custom-login","loginpress",
    "elementor","elementor-pro","divi-builder","beaver-builder",
    "visual-composer","king-composer","cornerstone","fusion-builder",
    "seed-prod","coming-soon","under-construction-page",
    "maintenance","wp-maintenance-mode","construction-coming-soon-maintenance",
    "caching-compatible-cookie-opt-in","uk-cookie-consent",
    "gdpr-cookie-compliance","cookiebot","cookie-yes",
    "wpml-media-translation","wpml-translation-management",
    "polylang-pro","qtranslate-xt","transposh-translation-filter",
    "wp-fastest-cache-premium","imagify","shortpixel",
    "ewww-image-optimizer","resmush-it","optimole","imagify",
    "wp-smush-pro","tinywebp","converter-for-media"
]

# Deduplicate while preserving order
TOP_PLUGINS = list(dict.fromkeys(TOP_PLUGINS))

TOP_THEMES = [
    "twentytwentyfour","twentytwentythree","twentytwentytwo",
    "twentytwentyone","twentytwenty","twentynineteen","twentyeighteen",
    "twentyseventeen","twentysixteen","twentyfifteen","twentyfourteen",
    "astra","oceanwp","generatepress","kadence","neve","storefront",
    "flatsome","divi","avada","woodmart","betheme","salient","enfold",
    "bridge","porto","electro","martfury","botiga","hello-elementor",
    "blocksy","colormag","sydney","hestia","shapely","inspiro",
    "spacious","total","optimizer","zakra","mesmerize",
]

# ─── WAF Signatures ────────────────────────────────────────────────────────────
WAF_SIGNATURES = {
    "Cloudflare":   ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status"],
    "Sucuri":       ["x-sucuri-id", "x-sucuri-cache", "sucuri/"],
    "Wordfence":    ["wordfence", "wfwaf-authcookie"],
    "ModSecurity":  ["mod_security", "modsecurity"],
    "AWS WAF":      ["x-amzn-requestid", "x-amz-cf-id"],
    "Akamai":       ["akamai", "x-akamai-transformed"],
    "Incapsula":    ["incap_ses", "visid_incap", "incapsula"],
    "F5 BIG-IP":    ["bigipserver", "f5-trafficshield"],
    "Imperva":      ["imperva", "x-iinfo"],
    "SiteLock":     ["sitelock"],
    "Barracuda":    ["barra_counter_session"],
    "Nginx+Lua":    ["naxsi", "ngx_lua_waf"],
}


class WPFingerprinter:
    def __init__(self, session, target, headers, timeout, output_dir, threads=10):
        self.session   = session
        self.target    = target
        self.headers   = headers
        self.timeout   = timeout
        self.output_dir = output_dir
        self.threads   = threads

    # ──────────────────────────────────────────────────────────────────────────
    def fingerprint(self) -> dict:
        """Run the full fingerprinting pipeline."""
        result = {
            "is_wordpress": False,
            "version": None,
            "version_sources": [],
            "plugins": {},
            "themes": [],
            "users": [],
            "xmlrpc_enabled": False,
            "rest_api_enabled": False,
            "waf": None,
            "security_headers": {},
            "interesting_paths": [],
            "robots_txt": None,
            "registration_open": False,
            "readme_exposed": False,
            "debug_enabled": False,
            "login_page": None,
        }

        # 1. Fetch homepage
        resp = safe_request(self.session, self.target, headers=self.headers,
                            timeout=self.timeout)
        if resp is None:
            print_error(f"Cannot reach {self.target}")
            return result

        # 2. WAF detection (from response headers)
        result["waf"] = self._detect_waf(resp)
        if result["waf"]:
            print_warning(f"WAF detected: {result['waf']} — applying bypass headers")
            self.headers = {**self.headers, **self._waf_bypass_headers()}

        # 3. Security headers
        result["security_headers"] = self._check_security_headers(resp)

        # 4. Detect WordPress
        result["is_wordpress"] = self._is_wordpress(resp)
        if not result["is_wordpress"]:
            print_warning("Target does not appear to be a WordPress site")
            return result
        print_success("WordPress detected!")

        # 5. Version detection (10+ methods)
        version, sources = self._detect_version(resp)
        result["version"] = version
        result["version_sources"] = sources
        if version:
            print_success(f"WordPress version: {W}{version}{RESET} (from: {', '.join(sources)})")
        else:
            print_warning("WordPress version could not be determined")

        # 6. Plugins
        print_info("Enumerating plugins (passive + active)…")
        result["plugins"] = self._enumerate_plugins(resp)
        print_success(f"Plugins found: {len(result['plugins'])}")

        # 7. Themes
        result["themes"] = self._enumerate_themes(resp)
        print_success(f"Themes found: {len(result['themes'])}")

        # 8. Users
        print_info("Enumerating users…")
        result["users"] = self._enumerate_users()
        if result["users"]:
            print_success(f"Users found: {len(result['users'])} — "
                          + ", ".join(u.get("login","?") for u in result["users"][:5]))

        # 9. XML-RPC
        result["xmlrpc_enabled"] = self._check_xmlrpc()

        # 10. REST API
        result["rest_api_enabled"] = self._check_rest_api()

        # 11. Misc checks
        result["readme_exposed"]   = self._check_readme()
        result["registration_open"] = self._check_registration()
        result["debug_enabled"]    = self._check_debug(resp)
        result["robots_txt"]       = self._get_robots()
        result["login_page"]       = self._find_login_page()
        result["interesting_paths"] = self._find_interesting_paths()

        return result

    # ──────────────────────────────────────────────────────────────────────────
    # WAF DETECTION
    # ──────────────────────────────────────────────────────────────────────────
    def _detect_waf(self, resp) -> Optional[str]:
        combined = " ".join(
            list(resp.headers.keys()) + list(resp.headers.values())
        ).lower()
        body_lower = (resp.text or "").lower()
        for waf_name, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in combined or sig.lower() in body_lower:
                    return waf_name
        return None

    def _waf_bypass_headers(self) -> dict:
        """Return extra headers that may bypass simple WAF rules."""
        return {
            "X-Forwarded-For": "127.0.0.1",
            "X-Originating-IP": "127.0.0.1",
            "X-Remote-IP": "127.0.0.1",
            "X-Remote-Addr": "127.0.0.1",
            "X-Client-IP": "127.0.0.1",
        }

    # ──────────────────────────────────────────────────────────────────────────
    # SECURITY HEADERS
    # ──────────────────────────────────────────────────────────────────────────
    def _check_security_headers(self, resp) -> dict:
        important = [
            "X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection",
            "Strict-Transport-Security", "Content-Security-Policy",
            "Referrer-Policy", "Permissions-Policy", "Server",
        ]
        result = {}
        for h in important:
            result[h] = resp.headers.get(h, "MISSING")
        return result

    # ──────────────────────────────────────────────────────────────────────────
    # IS WORDPRESS?
    # ──────────────────────────────────────────────────────────────────────────
    def _is_wordpress(self, resp) -> bool:
        indicators = [
            "/wp-content/", "/wp-includes/",
            "wp-json", "wordpress", "wp-login",
            'name="generator" content="WordPress',
            "xmlrpc.php", "/wp-admin",
        ]
        body = resp.text.lower()
        for ind in indicators:
            if ind.lower() in body:
                return True
        # Check /wp-login.php
        login = safe_request(self.session, urljoin(self.target, "/wp-login.php"),
                             headers=self.headers, timeout=self.timeout)
        if login and "user_login" in login.text.lower():
            return True
        return False

    # ──────────────────────────────────────────────────────────────────────────
    # VERSION DETECTION (10+ methods)
    # ──────────────────────────────────────────────────────────────────────────
    def _detect_version(self, resp) -> Tuple[Optional[str], List[str]]:
        version = None
        sources = []

        def update(v, src):
            nonlocal version
            if v and (not version):
                version = v
                sources.append(src)
            elif v and version == v and src not in sources:
                sources.append(src)

        # Method 1: meta generator
        m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+([\d.]+)', resp.text, re.I)
        if m: update(m.group(1), "meta-generator")

        # Method 2: readme.html
        r = safe_request(self.session, urljoin(self.target, "/readme.html"),
                         headers=self.headers, timeout=self.timeout)
        if r and r.status_code == 200:
            m = re.search(r'Version\s+([\d.]+)', r.text)
            if m: update(m.group(1), "readme.html")

        # Method 3: RSS feed
        r = safe_request(self.session, urljoin(self.target, "/?feed=rss2"),
                         headers=self.headers, timeout=self.timeout)
        if r and r.status_code == 200:
            m = re.search(r'<generator>.*?WordPress/([\d.]+)', r.text, re.I)
            if m: update(m.group(1), "rss-feed")

        # Method 4: Atom feed
        r = safe_request(self.session, urljoin(self.target, "/?feed=atom"),
                         headers=self.headers, timeout=self.timeout)
        if r and r.status_code == 200:
            m = re.search(r'WordPress/([\d.]+)', r.text)
            if m: update(m.group(1), "atom-feed")

        # Method 5: wp-includes/js/jquery/jquery.js
        for jq_path in ["/wp-includes/js/jquery/jquery.js",
                         "/wp-includes/js/jquery/jquery.min.js"]:
            r = safe_request(self.session, urljoin(self.target, jq_path),
                             headers=self.headers, timeout=self.timeout)
            if r and r.status_code == 200:
                m = re.search(r'wp-includes.*?ver=([\d.]+)', resp.text)
                if m: update(m.group(1), "jquery-ver-param")
                break

        # Method 6: wp-login.php source
        r = safe_request(self.session, urljoin(self.target, "/wp-login.php"),
                         headers=self.headers, timeout=self.timeout)
        if r and r.status_code == 200:
            m = re.search(r'ver=([\d.]+)', r.text)
            if m: update(m.group(1), "wp-login-ver")

        # Method 7: Static resource ?ver= param in homepage
        for m in re.finditer(r'wp-includes[^"\']+\?ver=([\d.]+)', resp.text):
            update(m.group(1), "static-resource-ver")
            break

        # Method 8: wp-includes/css/dashicons.min.css
        r = safe_request(self.session, urljoin(self.target, "/wp-includes/css/dashicons.min.css"),
                         headers=self.headers, timeout=self.timeout)
        if r and r.status_code == 200:
            m = re.search(r'\*/\s*$', r.text[:500], re.M)
            # parse version from link tag in homepage
            m2 = re.search(r'dashicons\.min\.css\?ver=([\d.]+)', resp.text)
            if m2: update(m2.group(1), "dashicons-ver")

        # Method 9: /wp-admin/css/common.min.css
        m = re.search(r'common\.min\.css\?ver=([\d.]+)', resp.text)
        if m: update(m.group(1), "admin-common-ver")

        # Method 10: opengraph / HTML comments
        m = re.search(r'<!--\s*This\s+site\s+is\s+running\s+WordPress\s+([\d.]+)', resp.text, re.I)
        if m: update(m.group(1), "html-comment")

        # Method 11: /wp-cron.php redirect header analysis
        r = safe_request(self.session, urljoin(self.target, "/wp-cron.php"),
                         headers=self.headers, timeout=self.timeout, allow_redirects=False)
        if r and "location" in r.headers:
            m = re.search(r'WordPress/([\d.]+)', r.headers.get("location", ""))
            if m: update(m.group(1), "wp-cron-redirect")

        return version, sources

    # ──────────────────────────────────────────────────────────────────────────
    # PLUGIN ENUMERATION
    # ──────────────────────────────────────────────────────────────────────────
    def _enumerate_plugins(self, resp) -> Dict[str, dict]:
        plugins = {}

        # Passive: scan homepage HTML for wp-content/plugins/ references
        for m in re.finditer(r'/wp-content/plugins/([^/"\'<>\s]+)', resp.text):
            slug = m.group(1).rstrip('/')
            if slug not in plugins:
                plugins[slug] = {"name": slug, "version": None, "source": "passive"}

        # Extract versions from ?ver= params
        for m in re.finditer(r'/wp-content/plugins/([^/"\']+)/[^"\']+\?ver=([\d.]+)', resp.text):
            slug, ver = m.group(1), m.group(2)
            if slug in plugins:
                plugins[slug]["version"] = ver
            else:
                plugins[slug] = {"name": slug, "version": ver, "source": "passive-ver"}

        # Active: probe README.txt / readme.txt for installed plugins
        def probe_plugin(slug):
            for path in [
                f"/wp-content/plugins/{slug}/readme.txt",
                f"/wp-content/plugins/{slug}/README.txt",
                f"/wp-content/plugins/{slug}/{slug}.php",
            ]:
                url = urljoin(self.target, path)
                r = safe_request(self.session, url, headers=self.headers, timeout=self.timeout)
                if r and r.status_code == 200 and len(r.text) > 20:
                    ver = None
                    m = re.search(r'Stable tag:\s*([\d.]+)', r.text, re.I)
                    if not m:
                        m = re.search(r'Version:\s*([\d.]+)', r.text, re.I)
                    if m:
                        ver = m.group(1)
                    return slug, ver
            return None, None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = {ex.submit(probe_plugin, s): s for s in TOP_PLUGINS
                    if s not in plugins}
            for fut in concurrent.futures.as_completed(futs):
                slug, ver = fut.result()
                if slug:
                    entry = plugins.get(slug, {"name": slug, "version": None, "source": "active"})
                    entry["version"] = ver or entry.get("version")
                    entry["source"] = "active" if slug not in plugins else "passive+active"
                    plugins[slug] = entry

        return plugins

    # ──────────────────────────────────────────────────────────────────────────
    # THEME ENUMERATION
    # ──────────────────────────────────────────────────────────────────────────
    def _enumerate_themes(self, resp) -> List[dict]:
        themes = {}

        # Passive
        for m in re.finditer(r'/wp-content/themes/([^/"\'<>\s]+)', resp.text):
            slug = m.group(1).rstrip('/')
            if slug not in themes:
                themes[slug] = {"name": slug, "version": None, "source": "passive"}

        # Extract ?ver=
        for m in re.finditer(r'/wp-content/themes/([^/"\']+)/[^"\']+\?ver=([\d.]+)', resp.text):
            slug, ver = m.group(1), m.group(2)
            if slug in themes:
                themes[slug]["version"] = ver

        # Active probe for top themes
        def probe_theme(slug):
            url = urljoin(self.target, f"/wp-content/themes/{slug}/style.css")
            r = safe_request(self.session, url, headers=self.headers, timeout=self.timeout)
            if r and r.status_code == 200:
                ver = None
                m = re.search(r'Version:\s*([\d.]+)', r.text, re.I)
                if m: ver = m.group(1)
                name_m = re.search(r'Theme Name:\s*(.+)', r.text, re.I)
                name = name_m.group(1).strip() if name_m else slug
                return slug, name, ver
            return None, None, None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = {ex.submit(probe_theme, s): s for s in TOP_THEMES
                    if s not in themes}
            for fut in concurrent.futures.as_completed(futs):
                slug, name, ver = fut.result()
                if slug:
                    themes[slug] = {"name": name or slug, "version": ver, "source": "active"}

        return list(themes.values())

    # ──────────────────────────────────────────────────────────────────────────
    # USER ENUMERATION (4 methods)
    # ──────────────────────────────────────────────────────────────────────────
    def _enumerate_users(self) -> List[dict]:
        users = {}

        # Method 1: WP REST API /wp-json/wp/v2/users
        r = safe_request(self.session,
                         urljoin(self.target, "/wp-json/wp/v2/users?per_page=100"),
                         headers=self.headers, timeout=self.timeout)
        if r and r.status_code == 200:
            try:
                data = r.json()
                if isinstance(data, list):
                    for u in data:
                        uid = u.get("id", 0)
                        users[uid] = {
                            "id": uid,
                            "login": u.get("slug", ""),
                            "name": u.get("name", ""),
                            "source": "rest-api",
                        }
            except Exception:
                pass

        # Method 2: Author archive pages (?author=1..10)
        for i in range(1, 11):
            r = safe_request(self.session,
                             f"{self.target}/?author={i}",
                             headers=self.headers, timeout=self.timeout,
                             allow_redirects=True)
            if r and r.status_code == 200:
                m = re.search(r'author/([^/"\'<>]+)', r.url)
                if not m:
                    m = re.search(r'class="author vcard"><a[^>]+>([^<]+)', r.text)
                if m and i not in users:
                    login = m.group(1).strip()
                    users[i] = {"id": i, "login": login, "name": login, "source": "author-archive"}

        # Method 3: WP oEmbed API
        r = safe_request(self.session,
                         urljoin(self.target, "/wp-json/oembed/1.0/embed?url=" + self.target),
                         headers=self.headers, timeout=self.timeout)
        if r and r.status_code == 200:
            try:
                data = r.json()
                author = data.get("author_name")
                if author and author not in [u.get("name") for u in users.values()]:
                    next_id = max(users.keys(), default=0) + 1
                    users[next_id] = {"id": next_id, "login": author,
                                      "name": author, "source": "oembed"}
            except Exception:
                pass

        # Method 4: XML-RPC user enumeration
        r = safe_request(
            self.session,
            urljoin(self.target, "/xmlrpc.php"),
            method="POST",
            headers={**self.headers, "Content-Type": "text/xml"},
            data="""<?xml version="1.0"?>
<methodCall><methodName>wp.getUsers</methodName>
<params>
  <param><value><int>1</int></value></param>
  <param><value><string>admin</string></value></param>
  <param><value><string>x</string></value></param>
</params>
</methodCall>""",
            timeout=self.timeout,
        )
        if r and "faultString" not in r.text:
            for m in re.finditer(r'<member><name>user_login</name><value><string>([^<]+)</string></value></member>', r.text):
                uname = m.group(1)
                if uname not in [u.get("login") for u in users.values()]:
                    next_id = max(users.keys(), default=0) + 1
                    users[next_id] = {"id": next_id, "login": uname,
                                      "name": uname, "source": "xmlrpc"}

        return list(users.values())

    # ──────────────────────────────────────────────────────────────────────────
    # XML-RPC CHECK
    # ──────────────────────────────────────────────────────────────────────────
    def _check_xmlrpc(self) -> bool:
        r = safe_request(self.session,
                         urljoin(self.target, "/xmlrpc.php"),
                         headers=self.headers, timeout=self.timeout)
        if r and r.status_code == 200 and "xmlrpc" in r.text.lower():
            print_warning("XML-RPC is enabled (potential attack surface)")
            return True
        return False

    # ──────────────────────────────────────────────────────────────────────────
    # REST API CHECK
    # ──────────────────────────────────────────────────────────────────────────
    def _check_rest_api(self) -> bool:
        r = safe_request(self.session,
                         urljoin(self.target, "/wp-json/"),
                         headers=self.headers, timeout=self.timeout)
        if r and r.status_code == 200 and "wp/v2" in r.text:
            print_warning("REST API is enabled and exposed")
            return True
        return False

    # ──────────────────────────────────────────────────────────────────────────
    # MISC CHECKS
    # ──────────────────────────────────────────────────────────────────────────
    def _check_readme(self) -> bool:
        for path in ["/readme.html", "/README.html", "/readme.txt", "/README.txt"]:
            r = safe_request(self.session, urljoin(self.target, path),
                             headers=self.headers, timeout=self.timeout)
            if r and r.status_code == 200 and "wordpress" in r.text.lower():
                print_warning(f"Readme exposed: {path}")
                return True
        return False

    def _check_registration(self) -> bool:
        r = safe_request(self.session,
                         urljoin(self.target, "/wp-login.php?action=register"),
                         headers=self.headers, timeout=self.timeout)
        if r and r.status_code == 200 and "registration" in r.text.lower():
            return True
        return False

    def _check_debug(self, resp) -> bool:
        debug_signs = ["wp_debug", "php notice", "php warning", "php fatal",
                       "notice:", "warning:", "undefined variable"]
        body_lower = resp.text.lower()
        return any(sign in body_lower for sign in debug_signs)

    def _get_robots(self) -> Optional[str]:
        r = safe_request(self.session, urljoin(self.target, "/robots.txt"),
                         headers=self.headers, timeout=self.timeout)
        if r and r.status_code == 200 and len(r.text) < 5000:
            return r.text.strip()
        return None

    def _find_login_page(self) -> Optional[str]:
        candidates = [
            "/wp-login.php", "/wp-admin/", "/admin/",
            "/login/", "/admin-login/", "/wp-admin/admin-ajax.php",
        ]
        for path in candidates:
            r = safe_request(self.session, urljoin(self.target, path),
                             headers=self.headers, timeout=self.timeout,
                             allow_redirects=True)
            if r and r.status_code in (200, 302):
                return urljoin(self.target, path)
        return None

    def _find_interesting_paths(self) -> List[dict]:
        paths = [
            "/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.old",
            "/.env", "/.git/config", "/.git/HEAD", "/backup.zip",
            "/backup.tar.gz", "/db.sql", "/dump.sql", "/database.sql",
            "/wp-content/debug.log", "/wp-content/uploads/.htaccess",
            "/wp-json/wp/v2/users", "/wp-json/wp/v2/posts",
            "/xmlrpc.php", "/wp-cron.php", "/wp-trackback.php",
            "/.htaccess", "/server-status", "/phpinfo.php",
            "/wp-content/uploads/", "/wp-includes/",
        ]
        found = []
        def check(path):
            r = safe_request(self.session, urljoin(self.target, path),
                             headers=self.headers, timeout=self.timeout)
            if r and r.status_code in (200, 403):
                return path, r.status_code
            return None, None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            for path, code in ex.map(check, paths):
                if path:
                    found.append({"path": path, "status": code})
        return found
