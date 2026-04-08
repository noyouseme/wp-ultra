# WP-Ultra v2.0 — Advanced WordPress Security Scanner

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Author](https://img.shields.io/badge/Author-Who%20C29%3F-purple?style=flat-square)

> **Created by [Who C29?](https://github.com/noyouseme)**

> ⚠️ **Untuk Authorized Penetration Testing saja. Jangan gunakan pada target tanpa izin tertulis.**

---

## Fitur

| Fitur | Detail |
|---|---|
| Deteksi versi WP | 10+ metode (meta, readme, feed, static ver param, dll) |
| Plugin enumeration | Pasif + aktif probe 500+ plugin populer |
| Theme enumeration | Pasif + aktif probe style.css |
| WAF detection & bypass | Cloudflare, Sucuri, Wordfence, Akamai, dll + bypass headers otomatis |
| CVE matching | Built-in JSON database (real CVEs dengan CVSS score) |
| SQL Injection | Error-based, search form + comment form |
| XSS | Reflected XSS probe |
| LFI | Multi-param, multi-payload |
| XML-RPC multicall brute | 50 cred/request (sangat cepat) |
| Login brute force | wp-login.php + XML-RPC, custom wordlist |
| Exposed file scanner | 30+ sensitive paths dengan validasi konten |
| Directory listing | wp-content/uploads, plugins, themes, includes |
| Security headers | X-Frame-Options, CSP, HSTS, dll |
| User enumeration | REST API, author archive, oEmbed, XML-RPC |
| Risk scoring | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| Report | Console, HTML (dark mode), Markdown, JSON |
| Mass scan | Multi-target dari file, concurrent |

---

## Requirement

- Python **3.8+**
- VPS: Ubuntu 20.04+ / Debian 11+ / CentOS 8+

---

## Instalasi (VPS / Linux)

```bash
# Clone repo
git clone https://github.com/noyouseme/wp-ultra.git
cd wp-ultra

# Install dependencies
pip3 install -r requirements.txt

# Beri permission execute (opsional)
chmod +x wp_ultra.py
```

## Setup di VPS (First Time)

```bash
# Update sistem
apt update && apt install python3 python3-pip git -y

# Clone & install
git clone https://github.com/noyouseme/wp-ultra.git
cd wp-ultra
pip3 install -r requirements.txt

# Test
python3 wp_ultra.py --version
```

---

## Penggunaan

```bash
# Scan dasar
python3 wp_ultra.py -t example.com

# Scan + semua laporan
python3 wp_ultra.py -t example.com --report-format all

# Scan + exploit + brute force (default wordlist built-in)
python3 wp_ultra.py -t example.com --exploit --brute

# Brute force dengan wordlist custom
python3 wp_ultra.py -t example.com --brute --wordlist rockyou.txt --brute-user admin

# Mass scan dari file targets.txt
python3 wp_ultra.py -l targets.txt --threads 15 --report-format html

# Gunakan proxy (Burp Suite / SOCKS5)
python3 wp_ultra.py -t example.com --proxy http://127.0.0.1:8080 -v

# Scan verbose + output ke folder custom
python3 wp_ultra.py -t example.com -o /tmp/hasil_scan -v --report-format all
```

---

## Semua Opsi

```
  -t TARGET              Target URL atau domain
  -l TARGETS_FILE        File daftar target (mass scan, 1 target per baris)
  -o OUTPUT              Direktori output (default: auto)
  --threads N            Jumlah thread (default: 10)
  --timeout N            Timeout request detik (default: 20)
  --exploit              Aktifkan modul eksploitasi
  --brute                Aktifkan brute force login
  --brute-user USER      Username(s) untuk brute (pisah koma)
  --wordlist FILE        File wordlist password custom
  --proxy URL            Proxy URL (e.g. http://127.0.0.1:8080)
  --user-agent UA        Custom User-Agent
  --report-format FORMAT console | html | md | json | all
  --mass-output-dir DIR  Base direktori untuk mass scan results
  -v, --verbose          Output verbose
```

---

## Struktur Output

```
results_example.com_20240101_120000/
├── scan.log              # Log lengkap
├── wp_info.json          # Info WP: versi, plugin, tema, user
├── vulnerabilities.json  # CVE + active findings
├── exploitation.json     # Hasil exploit (jika --exploit)
├── brute_results.json    # Hasil brute (jika --brute)
├── report.html           # Laporan HTML dark mode
├── report.md             # Laporan Markdown
└── report.json           # Laporan JSON lengkap + risk score
```

---

## Credits

| | |
|---|---|
| **Author** | Who C29? |
| **GitHub** | [github.com/noyouseme](https://github.com/noyouseme) |
| **Version** | 2.0 |

---

## Disclaimer

Tool ini dibuat untuk **tujuan edukasi dan authorized security testing saja**.  
Penggunaan pada sistem tanpa izin adalah **tindakan ilegal**.  
Developer tidak bertanggung jawab atas penyalahgunaan alat ini.
