import asyncio
import aiohttp
import argparse
import sys
import os
import re
import time
import json
import csv
import signal
import hashlib
import random
import string
import logging
import threading
import itertools
import textwrap
import socket
import ssl
import struct
import gzip
import zlib
import brotli
import urllib.parse
import urllib.robotparser
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from typing import (
    Optional, List, Dict, Set, Tuple, Any,
    AsyncGenerator, Generator, Callable
)
from collections import defaultdict, Counter, OrderedDict
from dataclasses import dataclass, field
from enum import Enum, auto
from contextlib import asynccontextmanager


VERSION      = "3.1.0"
TOOL_NAME    = "Masqued"
DEFAULT_UA   = f"{TOOL_NAME}/{VERSION} (Web Directory Scanner)"
MAX_REDIRECTS = 5
DEFAULT_TIMEOUT  = 10
DEFAULT_THREADS  = 50
DEFAULT_DELAY    = 0.0
DEFAULT_DEPTH    = 3
DEFAULT_EXTENSIONS = ["php","html","htm","asp","aspx","jsp","js","json",
                       "txt","xml","pdf","zip","tar","gz","bak","old",
                       "conf","config","log","sql","db","sqlite","env",
                       "yaml","yml","ini","cfg","py","rb","sh","pl"]


BANNER = r"""
  __  __                        _
 |  \/  | __ _ ___  __ _ _   _| |__   ___| |
 | |\/| |/ _` / __|/ _` | | | | '_ \ / _ \ |
 | |  | | (_| \__ \ (_| | |_| | |_) |  __/ |
 |_|  |_|\__,_|___/\__, |\__,_|_.__/ \___|_|
                    |___/
 Web Directory Bruteforcer  v{version}
""".format(version=VERSION)


BUILTIN_WORDLIST = [
    "admin","administrator","login","logout","dashboard","panel","control",
    "cp","wp-admin","wp-login","wp-content","wp-includes","wordpress",
    "joomla","drupal","magento","shopify","laravel","symfony","django",
    "api","api/v1","api/v2","api/v3","rest","graphql","swagger","openapi",
    "docs","documentation","doc","help","support","faq","kb","wiki",
    "backup","bak","old","tmp","temp","cache","data","files","uploads",
    "images","img","static","assets","css","js","fonts","media","content",
    "includes","include","lib","library","vendor","node_modules","composer",
    "config","configuration","settings","conf","cfg","setup","install",
    "index","home","main","default","error","404","403","500",
    "test","testing","dev","development","staging","production","prod",
    "debug","trace","log","logs","access","error_log","access_log",
    "robots","sitemap","sitemap.xml","robots.txt","humans.txt",".htaccess",
    ".htpasswd",".env",".git",".svn",".hg","web.config","phpinfo.php",
    "info.php","phpinfo","server-status","server-info","elmah.axd",
    "trace.axd","status","health","healthcheck","ping","alive","version",
    "changelog","readme","readme.md","readme.txt","license","license.txt",
    "user","users","account","accounts","profile","profiles","member",
    "members","register","signup","signin","auth","oauth","sso","ldap",
    "forgot","reset","password","change-password","2fa","mfa","verify",
    "email","mail","mailbox","smtp","inbox","outbox","sent","draft",
    "search","find","query","lookup","filter","sort","list","view",
    "create","new","add","edit","update","delete","remove","destroy",
    "upload","download","export","import","report","reports","analytics",
    "stat","stats","statistics","metrics","monitor","monitoring","alert",
    "alerts","notification","notifications","event","events","log","audit",
    "cart","shop","store","checkout","payment","billing","invoice","order",
    "orders","product","products","catalog","category","categories","tag",
    "tags","review","reviews","rating","ratings","comment","comments",
    "forum","forums","thread","threads","post","posts","topic","topics",
    "news","blog","article","articles","press","feed","rss","atom",
    "gallery","portfolio","project","projects","service","services",
    "contact","about","team","company","careers","jobs","pricing","plan",
    "plans","terms","privacy","cookie","disclaimer","legal","copyright",
    "download","downloads","file","files","attachment","attachments",
    "share","social","connect","follow","like","subscribe","unsubscribe",
    "ajax","async","xhr","fetch","webhook","callback","handler","action",
    "cron","task","job","queue","worker","daemon","bot","spider","crawler",
    "phpmyadmin","adminer","mysql","postgres","mongodb","redis","memcached",
    "elasticsearch","kibana","grafana","prometheus","jenkins","gitlab",
    "github","bitbucket","jira","confluence","sonar","nexus","artifactory",
    "console","terminal","shell","exec","execute","run","cmd","command",
    "proxy","gateway","router","firewall","vpn","tunnel","socket","ws",
    ".well-known","well-known","acme-challenge","security.txt","ads.txt",
    "apple-app-site-association","assetlinks.json","manifest.json",
    "browserconfig.xml","crossdomain.xml","clientaccesspolicy.xml",
    "web.config","Global.asax","default.aspx","index.aspx","login.aspx",
    "register.aspx","forgot.aspx","dashboard.aspx","admin.aspx",
    "includes/config.php","config/database.php","app/config","src","dist",
    "build","public","private","protected","hidden","secret","secure",
    "internal","external","intranet","extranet","portal","gateway",
    "server","client","backend","frontend","app","application","service",
    "microservice","lambda","function","serverless","cloud","infra",
]

INTERESTING_EXTENSIONS = {
    "php","asp","aspx","jsp","py","rb","pl","sh","cgi",
    "env","config","conf","cfg","ini","yaml","yml","json","xml",
    "sql","db","sqlite","mdb","bak","old","backup","tar","gz","zip","7z",
    "log","txt","csv","xls","xlsx","doc","docx","pdf",
    "pem","key","crt","cert","pfx","p12","jks",
}

STATUS_COLORS = {
    200: "\033[92m",
    201: "\033[92m",
    204: "\033[92m",
    301: "\033[94m",
    302: "\033[94m",
    307: "\033[94m",
    308: "\033[94m",
    401: "\033[93m",
    403: "\033[93m",
    405: "\033[93m",
    500: "\033[91m",
    503: "\033[91m",
}

C_RESET   = "\033[0m"
C_BOLD    = "\033[1m"
C_DIM     = "\033[2m"
C_RED     = "\033[91m"
C_GREEN   = "\033[92m"
C_YELLOW  = "\033[93m"
C_BLUE    = "\033[94m"
C_MAGENTA = "\033[95m"
C_CYAN    = "\033[96m"
C_WHITE   = "\033[97m"
C_GRAY    = "\033[90m"


def disable_colors():
    global C_RESET, C_BOLD, C_DIM, C_RED, C_GREEN, C_YELLOW
    global C_BLUE, C_MAGENTA, C_CYAN, C_WHITE, C_GRAY
    global STATUS_COLORS
    C_RESET = C_BOLD = C_DIM = C_RED = C_GREEN = C_YELLOW = ""
    C_BLUE = C_MAGENTA = C_CYAN = C_WHITE = C_GRAY = ""
    STATUS_COLORS = defaultdict(str)


def cprint(msg: str, color: str = "", bold: bool = False, end: str = "\n"):
    prefix = (C_BOLD if bold else "") + color
    sys.stdout.write(f"{prefix}{msg}{C_RESET}{end}")
    sys.stdout.flush()


def sep(char: str = "-", w: int = 72, color: str = ""):
    cprint(char * w, color or C_GRAY)


def status_color(code: int) -> str:
    return STATUS_COLORS.get(code, C_GRAY)


class LogLevel(Enum):
    SILENT  = 0
    MINIMAL = 1
    NORMAL  = 2
    VERBOSE = 3
    DEBUG   = 4


@dataclass
class ScanResult:
    url:           str
    path:          str
    status:        int
    size:          int
    redirect:      str = ""
    content_type:  str = ""
    server:        str = ""
    words:         int = 0
    lines:         int = 0
    elapsed_ms:    float = 0.0
    interesting:   bool = False
    depth:         int = 0
    method:        str = "GET"
    extra_headers: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "url":          self.url,
            "path":         self.path,
            "status":       self.status,
            "size":         self.size,
            "redirect":     self.redirect,
            "content_type": self.content_type,
            "server":       self.server,
            "words":        self.words,
            "lines":        self.lines,
            "elapsed_ms":   round(self.elapsed_ms, 2),
            "interesting":  self.interesting,
            "depth":        self.depth,
            "method":       self.method,
        }

    def display_line(self) -> str:
        sc   = status_color(self.status)
        size = f"{self.size:>8}" if self.size >= 0 else "      -1"
        redir = f"  -> {self.redirect[:50]}" if self.redirect else ""
        inter = f" {C_YELLOW}[!]{C_RESET}" if self.interesting else ""
        return (
            f"  {sc}{self.status}{C_RESET}"
            f"  {C_CYAN}{self.path:<55}{C_RESET}"
            f"  {C_GRAY}{size}B{C_RESET}"
            f"  {C_GRAY}{self.elapsed_ms:>6.0f}ms{C_RESET}"
            f"{redir}{inter}"
        )


class UserAgentPool:
    AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        DEFAULT_UA,
    ]

    def __init__(self, rotate: bool = False, custom: str = ""):
        self.rotate = rotate
        self.custom = custom
        self._idx   = 0
        self._lock  = threading.Lock()

    def get(self) -> str:
        if self.custom:
            return self.custom
        if not self.rotate:
            return DEFAULT_UA
        with self._lock:
            ua = self.AGENTS[self._idx % len(self.AGENTS)]
            self._idx += 1
        return ua


class RateLimiter:
    def __init__(self, rps: float = 0.0):
        self.delay   = 1.0 / rps if rps > 0 else 0.0
        self._last   = 0.0
        self._lock   = asyncio.Lock()

    async def wait(self):
        if self.delay <= 0:
            return
        async with self._lock:
            now     = time.monotonic()
            elapsed = now - self._last
            if elapsed < self.delay:
                await asyncio.sleep(self.delay - elapsed)
            self._last = time.monotonic()


class WildcardDetector:
    def __init__(self, base_url: str, session: aiohttp.ClientSession,
                 timeout: int = DEFAULT_TIMEOUT):
        self.base_url   = base_url.rstrip("/")
        self.session    = session
        self.timeout    = aiohttp.ClientTimeout(total=timeout)
        self.sizes:     Set[int] = set()
        self.hashes:    Set[str] = set()
        self.statuses:  Set[int] = set()
        self.detected   = False

    async def probe(self) -> bool:
        probes = [
            "/" + "".join(random.choices(string.ascii_lowercase, k=16)),
            "/" + "".join(random.choices(string.digits, k=12)) + ".php",
            "/this-path-does-not-exist-" + str(int(time.time())),
        ]
        for path in probes:
            url = self.base_url + path
            try:
                async with self.session.get(
                    url, timeout=self.timeout, allow_redirects=True
                ) as resp:
                    body = await resp.read()
                    self.sizes.add(len(body))
                    self.hashes.add(hashlib.md5(body).hexdigest())
                    self.statuses.add(resp.status)
            except Exception:
                pass

        if len(self.statuses) == 1 and 200 in self.statuses:
            self.detected = True

        if len(self.sizes) == 1 and self.sizes != {0}:
            self.detected = True

        return self.detected

    def is_wildcard(self, status: int, size: int, body_hash: str) -> bool:
        if not self.detected:
            return False
        if status in self.statuses and size in self.sizes:
            return True
        if body_hash in self.hashes:
            return True
        return False


class RobotsParser:
    def __init__(self, base_url: str, session: aiohttp.ClientSession,
                 timeout: int = DEFAULT_TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.session  = session
        self.timeout  = aiohttp.ClientTimeout(total=timeout)
        self.paths:   List[str] = []
        self.sitemaps: List[str] = []

    async def fetch(self) -> List[str]:
        url = self.base_url + "/robots.txt"
        try:
            async with self.session.get(url, timeout=self.timeout) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="ignore")
                    for line in text.splitlines():
                        line = line.strip()
                        if line.lower().startswith("disallow:"):
                            path = line.split(":", 1)[1].strip()
                            if path and path != "/":
                                self.paths.append(path.lstrip("/"))
                        elif line.lower().startswith("allow:"):
                            path = line.split(":", 1)[1].strip()
                            if path and path != "/":
                                self.paths.append(path.lstrip("/"))
                        elif line.lower().startswith("sitemap:"):
                            sm = line.split(":", 1)[1].strip()
                            self.sitemaps.append(sm)
        except Exception:
            pass
        return self.paths

    async def fetch_sitemaps(self) -> List[str]:
        paths = []
        sitemap_urls = self.sitemaps or [self.base_url + "/sitemap.xml"]
        for sm_url in sitemap_urls:
            try:
                async with self.session.get(
                    sm_url, timeout=self.timeout
                ) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="ignore")
                        for match in re.findall(r"<loc>(.*?)</loc>", text):
                            parsed = urllib.parse.urlparse(match)
                            p = parsed.path.lstrip("/")
                            if p:
                                paths.append(p)
            except Exception:
                pass
        return paths


class ContentExtractor:
    LINK_PATTERNS = [
        re.compile(r'href=["\']([^"\']+)["\']', re.I),
        re.compile(r'src=["\']([^"\']+)["\']', re.I),
        re.compile(r'action=["\']([^"\']+)["\']', re.I),
        re.compile(r'url\(["\']?([^"\')\s]+)["\']?\)', re.I),
        re.compile(r'"(\/[a-zA-Z0-9_\-./]+)"'),
        re.compile(r"'(\/[a-zA-Z0-9_\-./]+)'"),
        re.compile(r'location\.href\s*=\s*["\']([^"\']+)["\']', re.I),
        re.compile(r'window\.location\s*=\s*["\']([^"\']+)["\']', re.I),
        re.compile(r'fetch\(["\']([^"\']+)["\']', re.I),
        re.compile(r'axios\.\w+\(["\']([^"\']+)["\']', re.I),
    ]

    JS_PATH_PATTERN = re.compile(
        r'["\'](?P<path>/[a-zA-Z0-9_\-./]{2,})["\']'
    )

    def __init__(self, base_url: str):
        self.base_url  = base_url.rstrip("/")
        self.base_host = urllib.parse.urlparse(base_url).netloc

    def extract(self, html: str, current_url: str = "") -> Set[str]:
        paths: Set[str] = set()
        base  = current_url or self.base_url

        for pattern in self.LINK_PATTERNS:
            for match in pattern.finditer(html):
                href = match.group(1).strip()
                if not href or href.startswith(("#","mailto:","tel:","javascript:")):
                    continue
                resolved = urllib.parse.urljoin(base, href)
                parsed   = urllib.parse.urlparse(resolved)
                if parsed.netloc and parsed.netloc != self.base_host:
                    continue
                path = parsed.path.lstrip("/")
                if path and not path.startswith(("http","//","data:")):
                    paths.add(path)

        for match in self.JS_PATH_PATTERN.finditer(html):
            path = match.group("path").lstrip("/")
            if path and len(path) > 2:
                paths.add(path)

        return paths

    def extract_forms(self, html: str) -> List[Dict]:
        forms = []
        for form_match in re.finditer(
            r"<form[^>]*>(.*?)</form>", html, re.I | re.S
        ):
            form_html = form_match.group(0)
            action = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
            method = re.search(r'method=["\']([^"\']*)["\']', form_html, re.I)
            forms.append({
                "action": action.group(1) if action else "",
                "method": (method.group(1) if method else "GET").upper(),
            })
        return forms

    def extract_comments(self, html: str) -> List[str]:
        return re.findall(r"<!--(.*?)-->", html, re.S)

    def extract_emails(self, html: str) -> List[str]:
        return re.findall(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", html
        )

    def extract_api_endpoints(self, text: str) -> Set[str]:
        endpoints: Set[str] = set()
        patterns = [
            re.compile(r'/api/v\d+/[a-zA-Z0-9_\-/]+'),
            re.compile(r'/rest/[a-zA-Z0-9_\-/]+'),
            re.compile(r'/graphql[a-zA-Z0-9_\-/]*'),
            re.compile(r'/webhook[a-zA-Z0-9_\-/]*'),
        ]
        for p in patterns:
            for m in p.finditer(text):
                endpoints.add(m.group(0).lstrip("/"))
        return endpoints


class WordlistGenerator:
    def __init__(self):
        self._words: List[str] = []

    def load_file(self, path: str) -> int:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Wordlist not found: {path}")
        count = 0
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip()
                if word and not word.startswith("#"):
                    self._words.append(word)
                    count += 1
        return count

    def load_builtin(self):
        self._words.extend(BUILTIN_WORDLIST)

    def add_extensions(self, extensions: List[str]) -> List[str]:
        expanded = []
        for word in self._words:
            expanded.append(word)
            if "." not in word:
                for ext in extensions:
                    expanded.append(f"{word}.{ext}")
        return expanded

    def add_mutations(self, words: List[str]) -> List[str]:
        mutated = list(words)
        suffixes = ["1","2","_old","_bak","_backup","_test","_dev","-old","-bak"]
        for word in list(words):
            for sfx in suffixes:
                mutated.append(word + sfx)
        return mutated

    def generate(self, extensions: List[str] = None,
                 mutate: bool = False) -> List[str]:
        base = self._words[:]
        if extensions:
            base = self.add_extensions(extensions)
        if mutate:
            base = self.add_mutations(base)
        seen = OrderedDict()
        for w in base:
            seen[w] = None
        return list(seen.keys())

    @property
    def count(self) -> int:
        return len(self._words)


class ScanStats:
    def __init__(self):
        self.total_requests  = 0
        self.found           = 0
        self.errors          = 0
        self.start_time      = time.monotonic()
        self.status_counts:  Counter = Counter()
        self.size_total      = 0
        self._lock           = threading.Lock()

    def record(self, result: ScanResult):
        with self._lock:
            self.total_requests += 1
            self.status_counts[result.status] += 1
            if result.size > 0:
                self.size_total += result.size
            if result.status in (200,201,204,301,302,307,308,401,403,405):
                self.found += 1

    def record_error(self):
        with self._lock:
            self.total_requests += 1
            self.errors += 1

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.start_time

    @property
    def rps(self) -> float:
        e = self.elapsed
        return self.total_requests / e if e > 0 else 0.0

    def display(self):
        sep("=")
        cprint("  Scan Summary", C_BOLD + C_WHITE)
        sep()
        pad = 22
        cprint(f"  {'Total requests':<{pad}} {self.total_requests:,}", C_WHITE)
        cprint(f"  {'Found':<{pad}} {self.found:,}", C_GREEN)
        cprint(f"  {'Errors':<{pad}} {self.errors:,}", C_RED if self.errors else C_GRAY)
        cprint(f"  {'Elapsed':<{pad}} {self.elapsed:.2f}s", C_WHITE)
        cprint(f"  {'Avg RPS':<{pad}} {self.rps:.1f}", C_CYAN)
        cprint(f"  {'Data transferred':<{pad}} {self.size_total/1024:.1f} KB", C_WHITE)
        if self.status_counts:
            cprint(f"\n  Status code distribution:", C_DIM)
            for code in sorted(self.status_counts):
                bar = "#" * min(self.status_counts[code], 40)
                cprint(
                    f"    {status_color(code)}{code}{C_RESET}"
                    f"  {bar}  {self.status_counts[code]:,}"
                )
        sep("=")


class OutputManager:
    def __init__(self, output_file: Optional[str] = None,
                 fmt: str = "txt"):
        self.output_file  = output_file
        self.fmt          = fmt
        self._results:    List[ScanResult] = []
        self._lock        = threading.Lock()

    def add(self, result: ScanResult):
        with self._lock:
            self._results.append(result)

    def save(self):
        if not self.output_file:
            return
        p   = Path(self.output_file)
        fmt = self.fmt.lower()
        if fmt == "json" or p.suffix == ".json":
            self._save_json(p)
        elif fmt == "csv" or p.suffix == ".csv":
            self._save_csv(p)
        elif fmt == "md" or p.suffix == ".md":
            self._save_markdown(p)
        else:
            self._save_txt(p)
        cprint(f"\n  Results saved to {p}", C_GREEN)

    def _save_txt(self, p: Path):
        with open(p, "w", encoding="utf-8") as f:
            f.write(f"# {TOOL_NAME} v{VERSION} - Scan Results\n")
            f.write(f"# Generated: {datetime.utcnow().isoformat()}Z\n\n")
            for r in self._results:
                redir = f" -> {r.redirect}" if r.redirect else ""
                f.write(f"{r.status}  {r.url}{redir}  [{r.size}B]\n")

    def _save_json(self, p: Path):
        with open(p, "w", encoding="utf-8") as f:
            json.dump({
                "meta": {
                    "tool":      TOOL_NAME,
                    "version":   VERSION,
                    "generated": datetime.utcnow().isoformat() + "Z",
                    "count":     len(self._results),
                },
                "results": [r.to_dict() for r in self._results],
            }, f, indent=2)

    def _save_csv(self, p: Path):
        with open(p, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, fieldnames=["url","path","status","size","redirect",
                               "content_type","server","elapsed_ms",
                               "interesting","depth","method"]
            )
            writer.writeheader()
            writer.writerows([r.to_dict() for r in self._results])

    def _save_markdown(self, p: Path):
        with open(p, "w", encoding="utf-8") as f:
            f.write(f"# {TOOL_NAME} Scan Results\n\n")
            f.write(f"**Generated:** {datetime.utcnow().isoformat()}Z\n\n")
            f.write("| Status | Path | Size | Type | Interesting |\n")
            f.write("|--------|------|------|------|-------------|\n")
            for r in self._results:
                f.write(
                    f"| {r.status} | `{r.path}` | {r.size}B "
                    f"| {r.content_type[:30]} | {'yes' if r.interesting else ''} |\n"
                )

    @property
    def count(self) -> int:
        return len(self._results)


class DnsResolver:
    def __init__(self):
        self._cache: Dict[str, Optional[str]] = {}

    def resolve(self, host: str) -> Optional[str]:
        if host in self._cache:
            return self._cache[host]
        try:
            ip = socket.gethostbyname(host)
            self._cache[host] = ip
            return ip
        except socket.gaierror:
            self._cache[host] = None
            return None

    def reverse(self, ip: str) -> Optional[str]:
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return None


class TechFingerprinter:
    SIGNATURES: Dict[str, List[Tuple[str, str]]] = {
        "WordPress":    [("x-powered-by", ""), ("server", ""), ("body", "wp-content")],
        "Joomla":       [("body", "joomla"), ("body", "com_content")],
        "Drupal":       [("x-generator", "Drupal"), ("body", "drupal")],
        "Laravel":      [("set-cookie", "laravel_session")],
        "Django":       [("x-frame-options", "SAMEORIGIN"), ("body", "csrfmiddlewaretoken")],
        "ASP.NET":      [("x-aspnet-version", ""), ("x-powered-by", "ASP.NET")],
        "PHP":          [("x-powered-by", "PHP")],
        "nginx":        [("server", "nginx")],
        "Apache":       [("server", "Apache")],
        "IIS":          [("server", "Microsoft-IIS")],
        "Cloudflare":   [("server", "cloudflare"), ("cf-ray", "")],
        "AWS":          [("x-amz-", ""), ("server", "AmazonS3")],
        "Next.js":      [("x-powered-by", "Next.js")],
        "Express":      [("x-powered-by", "Express")],
        "Fastly":       [("x-served-by", "cache-"), ("x-cache", "")],
    }

    def detect(self, headers: Dict[str, str], body: str) -> List[str]:
        detected = []
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        body_lower    = body.lower()
        for tech, sigs in self.SIGNATURES.items():
            for header_name, value in sigs:
                if header_name == "body":
                    if value in body_lower:
                        detected.append(tech)
                        break
                else:
                    hv = headers_lower.get(header_name, "")
                    if value == "" and hv:
                        detected.append(tech)
                        break
                    elif value and value.lower() in hv:
                        detected.append(tech)
                        break
        return list(set(detected))


class ProbeManager:
    PROBES = {
        "trace":  ("TRACE",  "/"),
        "options":("OPTIONS","/"),
        "put":    ("PUT",    "/probe-test-{rand}"),
        "delete": ("DELETE", "/probe-test-{rand}"),
        "patch":  ("PATCH",  "/probe-test-{rand}"),
    }

    def __init__(self, base_url: str, session: aiohttp.ClientSession,
                 timeout: int = DEFAULT_TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.session  = session
        self.timeout  = aiohttp.ClientTimeout(total=timeout)

    async def probe_methods(self) -> Dict[str, int]:
        results = {}
        rand    = "".join(random.choices(string.ascii_lowercase, k=8))
        for name, (method, path) in self.PROBES.items():
            url = self.base_url + path.format(rand=rand)
            try:
                async with self.session.request(
                    method, url, timeout=self.timeout, allow_redirects=False
                ) as resp:
                    results[method] = resp.status
            except Exception:
                results[method] = -1
        return results


class Scanner:
    def __init__(self, config: Dict):
        self.config      = config
        self.base_url    = config["target"].rstrip("/")
        self.concurrency = config.get("threads", DEFAULT_THREADS)
        self.timeout_sec = config.get("timeout", DEFAULT_TIMEOUT)
        self.delay       = config.get("delay", DEFAULT_DELAY)
        self.rps         = config.get("rps", 0.0)
        self.follow_redirects = config.get("follow_redirects", True)
        self.log_level   = config.get("log_level", LogLevel.NORMAL)
        self.valid_codes = set(config.get("valid_codes",
                               [200,201,204,301,302,307,308,401,403,405,500]))
        self.excluded_codes = set(config.get("excluded_codes", []))
        self.valid_codes -= self.excluded_codes
        self.methods     = config.get("methods", ["GET"])
        self.headers     = config.get("headers", {})
        self.cookies     = config.get("cookies", {})
        self.proxy       = config.get("proxy", "")
        self.verify_ssl  = config.get("verify_ssl", False)
        self.ua_pool     = UserAgentPool(
            rotate = config.get("rotate_ua", False),
            custom = config.get("user_agent", ""),
        )
        self.rate_limiter = RateLimiter(self.rps)
        self.stats        = ScanStats()
        self.output       = OutputManager(
            output_file = config.get("output"),
            fmt         = config.get("output_format", "txt"),
        )
        self.extractor    = ContentExtractor(self.base_url)
        self.fingerprinter = TechFingerprinter()
        self._discovered: Set[str] = set()
        self._queue:      asyncio.Queue = asyncio.Queue()
        self._semaphore   = asyncio.Semaphore(self.concurrency)
        self._stop        = asyncio.Event()
        self._session:    Optional[aiohttp.ClientSession] = None
        self._wildcard:   Optional[WildcardDetector] = None
        self._technologies: Set[str] = set()
        self._depth_map:  Dict[str, int] = {}
        self.max_depth    = config.get("max_depth", DEFAULT_DEPTH)

    def _build_session(self) -> aiohttp.ClientSession:
        connector = aiohttp.TCPConnector(
            ssl           = False if not self.verify_ssl else None,
            limit         = self.concurrency * 2,
            limit_per_host= self.concurrency,
            ttl_dns_cache = 300,
            use_dns_cache = True,
            enable_cleanup_closed = True,
        )
        timeout = aiohttp.ClientTimeout(
            total          = self.timeout_sec,
            connect        = min(5, self.timeout_sec),
            sock_read      = self.timeout_sec,
        )
        default_headers = {
            "User-Agent":      self.ua_pool.get(),
            "Accept":          "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection":      "keep-alive",
        }
        default_headers.update(self.headers)

        cookie_jar = aiohttp.CookieJar(unsafe=True)

        session = aiohttp.ClientSession(
            connector   = connector,
            timeout     = timeout,
            headers     = default_headers,
            cookie_jar  = cookie_jar,
            trust_env   = True,
        )
        for k, v in self.cookies.items():
            session.cookie_jar.update_cookies({k: v})

        return session

    async def _request(self, url: str, method: str = "GET") -> Optional[ScanResult]:
        await self.rate_limiter.wait()
        if self.delay > 0:
            await asyncio.sleep(self.delay + random.uniform(0, self.delay * 0.1))

        headers = {"User-Agent": self.ua_pool.get()}
        start   = time.monotonic()
        path    = urllib.parse.urlparse(url).path

        try:
            async with self._semaphore:
                proxy = self.proxy or None
                async with self._session.request(
                    method,
                    url,
                    headers     = headers,
                    allow_redirects = self.follow_redirects,
                    proxy       = proxy,
                    max_redirects = MAX_REDIRECTS,
                ) as resp:
                    elapsed = (time.monotonic() - start) * 1000
                    try:
                        body = await resp.read()
                    except Exception:
                        body = b""

                    body_text = ""
                    try:
                        body_text = body.decode("utf-8", errors="ignore")
                    except Exception:
                        pass

                    ct   = resp.headers.get("Content-Type","")
                    srv  = resp.headers.get("Server","")
                    size = int(resp.headers.get("Content-Length", len(body)))

                    redirect = ""
                    if resp.history:
                        redirect = str(resp.url)

                    words = len(body_text.split()) if body_text else 0
                    lines = body_text.count("\n") if body_text else 0

                    bh     = hashlib.md5(body).hexdigest() if body else ""
                    is_wc  = False
                    if self._wildcard:
                        is_wc = self._wildcard.is_wildcard(resp.status, size, bh)

                    if is_wc:
                        return None

                    ext = Path(path).suffix.lstrip(".").lower()
                    interesting = (
                        ext in INTERESTING_EXTENSIONS
                        or resp.status in (401, 403, 500)
                        or any(k in body_text.lower() for k in
                               ["password","secret","token","api_key","private"])
                        or "index of" in body_text.lower()
                    )

                    result = ScanResult(
                        url          = url,
                        path         = path.lstrip("/") or "/",
                        status       = resp.status,
                        size         = size,
                        redirect     = redirect,
                        content_type = ct.split(";")[0].strip(),
                        server       = srv,
                        words        = words,
                        lines        = lines,
                        elapsed_ms   = elapsed,
                        interesting  = interesting,
                        depth        = self._depth_map.get(path.lstrip("/"), 0),
                        method       = method,
                    )

                    techs = self.fingerprinter.detect(
                        dict(resp.headers), body_text
                    )
                    self._technologies.update(techs)

                    if resp.status in (200, 201) and body_text:
                        extracted = self.extractor.extract(
                            body_text, str(resp.url)
                        )
                        current_depth = result.depth
                        if current_depth < self.max_depth:
                            for new_path in extracted:
                                if new_path not in self._discovered:
                                    self._discovered.add(new_path)
                                    new_url = self.base_url + "/" + new_path.lstrip("/")
                                    self._depth_map[new_path] = current_depth + 1
                                    await self._queue.put(new_url)

                    return result

        except asyncio.TimeoutError:
            self.stats.record_error()
            if self.log_level >= LogLevel.DEBUG:
                cprint(f"  [timeout]  {url}", C_GRAY)
            return None
        except aiohttp.ClientError as exc:
            self.stats.record_error()
            if self.log_level >= LogLevel.DEBUG:
                cprint(f"  [error]  {url}  {exc}", C_GRAY)
            return None
        except Exception as exc:
            self.stats.record_error()
            if self.log_level >= LogLevel.DEBUG:
                cprint(f"  [fatal]  {url}  {exc}", C_RED)
            return None

    async def _worker(self):
        while not self._stop.is_set():
            try:
                url = await asyncio.wait_for(
                    self._queue.get(), timeout=2.0
                )
            except asyncio.TimeoutError:
                if self._queue.empty():
                    break
                continue

            for method in self.methods:
                result = await self._request(url, method)
                if result:
                    if result.status in self.valid_codes:
                        self.stats.record(result)
                        self.output.add(result)
                        if self.log_level >= LogLevel.MINIMAL:
                            cprint(result.display_line())

            self._queue.task_done()

    async def _preflight(self):
        cprint(f"  Preflight check...", C_DIM)
        try:
            async with self._session.get(
                self.base_url,
                timeout = aiohttp.ClientTimeout(total=10),
                allow_redirects=True,
            ) as resp:
                body = await resp.text(errors="ignore")
                techs = self.fingerprinter.detect(dict(resp.headers), body)
                self._technologies.update(techs)
                status = resp.status
                srv    = resp.headers.get("Server","(none)")
                ct     = resp.headers.get("Content-Type","")
                cprint(f"  Target online  {status_color(status)}{status}{C_RESET}"
                       f"  server={C_CYAN}{srv}{C_RESET}", )
        except Exception as exc:
            cprint(f"  Preflight failed: {exc}", C_YELLOW)

    async def run(self, wordlist: List[str]):
        self._session = self._build_session()

        try:
            sep("=")
            cprint("  Initializing scan", C_BOLD + C_WHITE)
            sep()

            await self._preflight()

            self._wildcard = WildcardDetector(
                self.base_url, self._session, self.timeout_sec
            )
            wc = await self._wildcard.probe()
            if wc:
                cprint(
                    "  Wildcard detected - false positive filtering enabled",
                    C_YELLOW
                )

            robots_parser = RobotsParser(
                self.base_url, self._session, self.timeout_sec
            )
            robot_paths = await robots_parser.fetch()
            sitemap_paths = await robots_parser.fetch_sitemaps()

            extra = robot_paths + sitemap_paths
            if extra:
                cprint(
                    f"  Found {len(extra)} paths from robots/sitemap",
                    C_CYAN
                )
                for p in extra:
                    if p not in self._discovered:
                        self._discovered.add(p)
                        wordlist.append(p)

            total = len(wordlist)
            cprint(f"  Wordlist size  {total:,} entries", C_WHITE)
            cprint(f"  Concurrency    {self.concurrency}", C_WHITE)
            cprint(f"  Timeout        {self.timeout_sec}s", C_WHITE)
            cprint(f"  Methods        {', '.join(self.methods)}", C_WHITE)
            cprint(f"  Valid codes    {sorted(self.valid_codes)}", C_WHITE)
            if self.proxy:
                cprint(f"  Proxy          {self.proxy}", C_YELLOW)
            sep()

            header_line = (
                f"  {'STATUS':<8}  {'PATH':<55}  {'SIZE':>8}  {'TIME':>8}"
            )
            cprint(header_line, C_BOLD + C_GRAY)
            sep()

            for word in wordlist:
                url = self.base_url + "/" + word.lstrip("/")
                if url not in self._discovered:
                    self._discovered.add(url)
                    self._depth_map[word.lstrip("/")] = 0
                    await self._queue.put(url)

            workers = [
                asyncio.create_task(self._worker())
                for _ in range(min(self.concurrency, total))
            ]

            progress_task = asyncio.create_task(
                self._progress_reporter(total)
            )

            await self._queue.join()
            self._stop.set()

            for w in workers:
                w.cancel()
            progress_task.cancel()

            await asyncio.gather(*workers, return_exceptions=True)

        finally:
            await self._session.close()

        sep()
        if self._technologies:
            cprint(
                f"  Technologies: {C_CYAN}"
                + ", ".join(sorted(self._technologies))
                + C_RESET
            )

        self.stats.display()
        self.output.save()

        return self.output.count

    async def _progress_reporter(self, total: int):
        while not self._stop.is_set():
            await asyncio.sleep(5)
            q_size   = self._queue.qsize()
            done     = total - q_size
            if total > 0:
                pct  = done / total * 100
            else:
                pct  = 0
            cprint(
                f"\r  Progress  {done:>6}/{total}  ({pct:.1f}%)"
                f"  {self.stats.rps:.1f} req/s"
                f"  found={self.stats.found:,}",
                C_DIM, end=""
            )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME.lower(),
        description=f"{TOOL_NAME} - Professional web directory bruteforcer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            Examples:
              masqued https://example.com
              masqued https://example.com -w /usr/share/wordlists/dirb/common.txt
              masqued https://example.com -e php,asp,jsp -t 100 --brute
              masqued https://example.com --codes 200,301,403 -o results.json
              masqued https://example.com -x ".env,.git,.htaccess" --depth 4
              masqued https://example.com --proxy http://127.0.0.1:8080
              masqued https://example.com -m GET,POST,HEAD --rotate-ua
        """),
    )

    parser.add_argument("target",
                        help="Target URL (e.g. https://example.com)")
    parser.add_argument("-w", "--wordlist", metavar="FILE",
                        help="Wordlist file (one path per line)")
    parser.add_argument("-e", "--extensions", metavar="EXT",
                        help="Comma-separated extensions to append")
    parser.add_argument("-x", "--extra-paths", metavar="PATHS",
                        help="Comma-separated additional paths to test")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS,
                        metavar="N", help=f"Concurrent threads [{DEFAULT_THREADS}]")
    parser.add_argument("-T", "--timeout", type=int, default=DEFAULT_TIMEOUT,
                        metavar="N", help=f"Request timeout seconds [{DEFAULT_TIMEOUT}]")
    parser.add_argument("-d", "--delay", type=float, default=DEFAULT_DELAY,
                        metavar="F", help="Delay between requests (seconds)")
    parser.add_argument("--rps", type=float, default=0.0,
                        metavar="N", help="Max requests per second")
    parser.add_argument("--depth", type=int, default=DEFAULT_DEPTH,
                        metavar="N", help=f"Max crawl depth [{DEFAULT_DEPTH}]")
    parser.add_argument("-m", "--methods", default="GET",
                        metavar="M", help="HTTP methods (comma-separated)")
    parser.add_argument("--codes", default="200,201,204,301,302,307,308,401,403,405",
                        metavar="CODES", help="Valid status codes")
    parser.add_argument("--exclude-codes", default="",
                        metavar="CODES", help="Status codes to exclude")
    parser.add_argument("-H", "--header", action="append", default=[],
                        metavar="H:V", help="Custom headers (repeatable)")
    parser.add_argument("-C", "--cookie", default="",
                        metavar="NAME=VAL", help="Cookie(s) to send")
    parser.add_argument("-u", "--user-agent", default="",
                        metavar="UA", help="Custom User-Agent")
    parser.add_argument("--rotate-ua", action="store_true",
                        help="Rotate User-Agent strings")
    parser.add_argument("-p", "--proxy", default="",
                        metavar="URL", help="HTTP/S proxy URL")
    parser.add_argument("--no-ssl-verify", action="store_true",
                        help="Disable SSL verification")
    parser.add_argument("--brute", action="store_true",
                        help="Use built-in wordlist (no external file needed)")
    parser.add_argument("--mutate", action="store_true",
                        help="Apply wordlist mutations (add suffixes)")
    parser.add_argument("--no-robots", action="store_true",
                        help="Skip robots.txt and sitemap parsing")
    parser.add_argument("--no-wildcard", action="store_true",
                        help="Disable wildcard detection")
    parser.add_argument("--no-crawl", action="store_true",
                        help="Disable passive crawling of found pages")
    parser.add_argument("--follow-redirects", action="store_true", default=True,
                        help="Follow HTTP redirects")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Output file (.txt/.json/.csv/.md)")
    parser.add_argument("-f", "--format", choices=["txt","json","csv","md"],
                        default="txt", metavar="FMT", help="Output format")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable color output")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Quiet mode (found only)")
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {VERSION}")

    return parser


def parse_headers(raw: List[str]) -> Dict[str, str]:
    headers = {}
    for h in raw:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def parse_cookies(raw: str) -> Dict[str, str]:
    cookies = {}
    for item in raw.split(";"):
        item = item.strip()
        if "=" in item:
            k, v = item.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


def parse_codes(raw: str) -> Set[int]:
    codes: Set[int] = set()
    for part in raw.split(","):
        part = part.strip()
        if part.isdigit():
            codes.add(int(part))
    return codes


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://","https://")):
        url = "https://" + url
    return url.rstrip("/")


def print_banner():
    cprint(BANNER, C_CYAN, bold=True)


def handle_sigint(_sig, _frame):
    cprint("\n\n  Scan interrupted by user", C_YELLOW)
    sys.exit(130)


async def amain(args: argparse.Namespace):
    target = normalize_url(args.target)
    parsed = urllib.parse.urlparse(target)
    if not parsed.netloc:
        cprint(f"  Invalid target URL: {target}", C_RED)
        sys.exit(2)

    resolver = DnsResolver()
    host     = parsed.netloc.split(":")[0]
    ip       = resolver.resolve(host)

    cprint(f"  Target   {C_CYAN}{target}{C_RESET}")
    cprint(f"  Host     {host}")
    if ip:
        cprint(f"  IP       {C_YELLOW}{ip}{C_RESET}")
        reverse = resolver.reverse(ip)
        if reverse and reverse != host:
            cprint(f"  Reverse  {reverse}")

    extensions = []
    if args.extensions:
        extensions = [e.strip().lstrip(".") for e in args.extensions.split(",")]

    wl_gen = WordlistGenerator()
    if args.wordlist:
        n = wl_gen.load_file(args.wordlist)
        cprint(f"  Wordlist {args.wordlist} ({n:,} entries)")
    if args.brute or not args.wordlist:
        wl_gen.load_builtin()

    wordlist = wl_gen.generate(
        extensions = extensions if extensions else None,
        mutate     = args.mutate,
    )

    if args.extra_paths:
        for ep in args.extra_paths.split(","):
            ep = ep.strip().lstrip("/")
            if ep:
                wordlist.append(ep)

    if args.verbose:
        log_level = LogLevel.VERBOSE
    elif args.quiet:
        log_level = LogLevel.MINIMAL
    else:
        log_level = LogLevel.NORMAL

    config = {
        "target":           target,
        "threads":          args.threads,
        "timeout":          args.timeout,
        "delay":            args.delay,
        "rps":              args.rps,
        "max_depth":        args.depth,
        "methods":          [m.strip().upper() for m in args.methods.split(",")],
        "valid_codes":      parse_codes(args.codes),
        "excluded_codes":   parse_codes(args.exclude_codes) if args.exclude_codes else set(),
        "headers":          parse_headers(args.header),
        "cookies":          parse_cookies(args.cookie) if args.cookie else {},
        "user_agent":       args.user_agent,
        "rotate_ua":        args.rotate_ua,
        "proxy":            args.proxy,
        "verify_ssl":       not args.no_ssl_verify,
        "follow_redirects": args.follow_redirects,
        "output":           args.output,
        "output_format":    args.format,
        "log_level":        log_level,
    }

    scanner = Scanner(config)
    found   = await scanner.run(wordlist)
    return 0 if found > 0 else 1


def main():
    signal.signal(signal.SIGINT, handle_sigint)

    parser = build_parser()
    args   = parser.parse_args()

    if args.no_color or not (hasattr(sys.stdout, "isatty") and sys.stdout.isatty()):
        disable_colors()

    print_banner()

    try:
        import brotli
    except ImportError:
        pass

    exit_code = asyncio.run(amain(args))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
