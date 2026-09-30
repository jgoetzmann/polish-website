#!/usr/bin/env python3
"""Live URL probe: read-only checks against a deployed site (rules W01-W16).

    python3 scripts/probe.py URL [--anon-read] [--timeout 10] [--max-requests 150]
        [--only ID,area] [--format md|json] [--fail-on P0] [--out FILE] [--list-rules]

It is polite by construction: GET only, same origin only (plus the project's own
Supabase API under --anon-read), a hard cap on requests, and a timeout on each one.
It never follows a link off-site, never submits a form, and never prints a secret
value or a row of data: only redacted keys, counts, and column names.
"""

from __future__ import annotations

import argparse
import functools
import http.client
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (  # noqa: E402
    AREAS, JWT, SECRET_PATTERNS, Finding, add_output_args, emit, exit_code, find_secrets, jwt_payload, jwt_role,
    redact, render, rules_table,
)

TOOL = "probe.py"
USER_AGENT = "polish-website-probe/1.0 (+https://github.com/jgoetzmann/polish-website)"
PROBE_ORIGIN = "https://polish-website-probe.invalid"
# Fixed rather than random so two runs print the same report. No real route has this name.
NOT_FOUND_PATH = "/polish-website-404-check-7f3a9c"

MAX_JS_FILES = 40
MAX_CSS_FILES = 10
MAX_ASSET_BYTES = 5 * 1024 * 1024
PROBE_BYTES = 256 * 1024  # enough to validate an exposed file without downloading all of it
MAX_MAP_FETCHES = 10
MAX_MAP_GUESSES = 3
MAX_API_PATHS = 5
MAX_TABLES = 50
MAX_REDIRECTS = 5
MAX_CONSECUTIVE_FAILURES = 5  # a site that stopped answering shouldn't cost 150 timeouts
REDIRECT_CODES = (301, 302, 303, 307, 308)
DEFAULT_PORTS = {"http": 80, "https": 443}
LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")


# --- Fetch layer ---------------------------------------------------------------

@dataclass
class Response:
    url: str
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)  # lower-case names
    body: bytes = b""
    error: str = ""  # set when no HTTP response arrived
    redirected: bool = False
    offsite_location: str = ""  # a redirect we refused to follow

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")

    @functools.cached_property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def summary(self) -> str:
        if self.error:
            return self.error
        kind = self.header("content-type").split(";")[0].strip()
        return f"{self.status} {kind}".strip()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Hand every 3xx back to the caller, which decides whether the next hop is allowed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def origin_of(url: str) -> Tuple[str, str, Optional[int]]:
    try:
        parts = urllib.parse.urlsplit(url)
        scheme = parts.scheme.lower()
        return scheme, (parts.hostname or "").lower(), parts.port or DEFAULT_PORTS.get(scheme)
    except ValueError:
        return "", "", None


def origin_url(url: str) -> str:
    scheme, host, port = origin_of(url)
    host = f"[{host}]" if ":" in host else host
    return f"{scheme}://{host}" + ("" if port == DEFAULT_PORTS.get(scheme) else f":{port}")


def same_site(a: str, b: str) -> bool:
    """Same host give or take a leading www., over http or https, on the same or default ports."""
    (sa, ha, pa), (sb, hb, pb) = origin_of(a), origin_of(b)
    if sa not in DEFAULT_PORTS or sb not in DEFAULT_PORTS or ha.removeprefix("www.") != hb.removeprefix("www."):
        return False
    return pa == pb or (pa == DEFAULT_PORTS[sa] and pb == DEFAULT_PORTS[sb])


def header_dict(message) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for name, value in message.items():
        key = name.lower()
        out[key] = f"{out[key]}, {value}" if key in out else value
    return out


def describe_error(err: BaseException, timeout: float) -> str:
    reason = getattr(err, "reason", err)
    if isinstance(reason, socket.gaierror):
        return f"DNS lookup failed ({reason.strerror or reason})"
    if isinstance(reason, ssl.SSLCertVerificationError):
        return f"TLS certificate rejected ({reason.verify_message or reason})"
    if isinstance(reason, ssl.SSLError):
        return f"TLS handshake failed ({reason.reason or reason})"
    if isinstance(reason, ConnectionRefusedError):
        return "connection refused"
    if isinstance(reason, (socket.timeout, TimeoutError)) or "timed out" in str(reason):
        return f"timed out after {timeout:g}s"
    if isinstance(reason, ConnectionResetError):
        return "connection reset by the server"
    return f"{type(reason).__name__}: {reason}"


def bot_challenge(resp: "Response") -> str:
    """Name the bot challenge a response is, or return "" for a real page.

    A host's firewall (Vercel's Security Checkpoint, Cloudflare's challenge) answers scripted clients with
    its own page. Auditing that page reports the challenge's headers and markup as if they were the site's.
    """
    if resp.header("x-vercel-mitigated") == "challenge":
        return "Vercel Security Checkpoint, x-vercel-mitigated: challenge"
    if resp.header("cf-mitigated") == "challenge":
        return "Cloudflare challenge, cf-mitigated: challenge"
    if resp.status in (403, 429, 503) and re.search(r"Vercel Security Checkpoint|Just a moment\.\.\.|cf-chl-", resp.text[:20000]):
        return f"HTTP {resp.status} challenge page"
    return ""


class Fetcher:
    """GET-only HTTP client with a cache, a request counter, and an origin allowlist."""

    def __init__(self, timeout: float, max_requests: int):
        self.timeout = timeout
        self.max_requests = max_requests
        self.count = 0
        self.failed = 0
        self.failed_in_a_row = 0
        self.cap_hit = False
        self.allowed: Dict[str, set] = {"site": set(), "supabase": set()}
        self._cache: Dict[tuple, Response] = {}
        self._opener = urllib.request.build_opener(_NoRedirect())

    def allow(self, url: str, scope: str = "site") -> None:
        self.allowed[scope].add(origin_of(url))

    def get(self, url: str, headers: Optional[Dict[str, str]] = None, follow: bool = True,
            limit: int = MAX_ASSET_BYTES, scope: str = "site") -> Response:
        headers = headers or {}
        key = (url, tuple(sorted(headers.items())), follow, limit, scope)
        if key in self._cache:
            return self._cache[key]
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            if origin_of(current) not in self.allowed[scope]:
                resp = Response(current, error="not fetched: outside the probed origin")
                break
            resp = self._request(current, headers, limit)
            location = resp.header("location")
            if not follow or resp.status not in REDIRECT_CODES or not location:
                break
            nxt = urllib.parse.urljoin(current, location)
            if origin_of(nxt) not in self.allowed[scope]:
                resp.offsite_location = nxt
                break
            current = nxt
        resp.redirected = current != url
        self._cache[key] = resp
        return resp

    def _request(self, url: str, headers: Dict[str, str], limit: int) -> Response:
        if self.count >= self.max_requests:
            self.cap_hit = True
            return Response(url, error="request cap reached")
        if self.failed_in_a_row >= MAX_CONSECUTIVE_FAILURES:
            return Response(url, error=f"not sent: the last {MAX_CONSECUTIVE_FAILURES} requests failed")
        self.count += 1
        safe = urllib.parse.quote(url, safe=":/?#[]@!$&'()*+,;=%~")
        request = urllib.request.Request(safe, headers={"User-Agent": USER_AGENT, "Accept": "*/*", **headers}, method="GET")
        try:
            with self._opener.open(request, timeout=self.timeout) as r:
                resp = Response(url, r.status, header_dict(r.headers), r.read(limit))
        except urllib.error.HTTPError as e:  # 3xx/4xx/5xx still carry a real response
            try:
                body = e.read(limit)
            except (OSError, http.client.HTTPException):
                body = b""
            resp = Response(url, e.code, header_dict(e.headers), body)
        except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError) as e:
            self.failed += 1
            self.failed_in_a_row += 1
            return Response(url, error=describe_error(e, self.timeout))
        self.failed_in_a_row = 0
        return resp


# --- Page parsing --------------------------------------------------------------

class PageParser(HTMLParser):
    """Pull what the rules need out of one HTML document."""

    INVISIBLE = {"script", "style", "noscript", "template", "title"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.saw_html = False
        self.lang = ""
        self.title: Optional[str] = None
        self.metas: List[Dict[str, str]] = []
        self.links: List[Dict[str, str]] = []
        self.scripts: List[Dict[str, str]] = []
        self.inline_scripts: List[str] = []
        self.resources: List[Tuple[str, str]] = []  # (kind, url) that the browser loads
        self.h1 = 0
        self._text: List[str] = []
        self._invisible = 0
        self._svg = 0
        self._in_title = False
        self._script: Optional[List[str]] = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "html" and not self.saw_html:
            self.saw_html = True
            self.lang = a.get("lang", "").strip()
        elif tag == "svg":
            self._svg += 1
        elif tag == "title" and self.title is None and not self._svg:
            self.title = ""
            self._in_title = True
        elif tag == "meta":
            self.metas.append(a)
        elif tag == "link":
            self.links.append(a)
            if "stylesheet" in a.get("rel", "").lower().split() and a.get("href"):
                self.resources.append(("stylesheet", a["href"]))
        elif tag == "script":
            self.scripts.append(a)
            self._script = []
            if a.get("src"):
                self.resources.append(("script", a["src"]))
        elif tag == "h1":
            self.h1 += 1
        elif tag in ("img", "source"):
            if tag == "img" and a.get("src"):
                self.resources.append(("image", a["src"]))
            for candidate in a.get("srcset", "").split(","):
                if candidate.strip():
                    self.resources.append(("image", candidate.split()[0]))
        elif tag == "iframe" and a.get("src"):
            self.resources.append(("iframe", a["src"]))
        if tag in self.INVISIBLE:
            self._invisible += 1

    def handle_endtag(self, tag):
        if tag in self.INVISIBLE and self._invisible:
            self._invisible -= 1
        if tag == "svg" and self._svg:
            self._svg -= 1
        elif tag == "title":
            self._in_title = False
        elif tag == "script" and self._script is not None:
            self.inline_scripts.append("".join(self._script))
            self._script = None

    def handle_data(self, data):
        if self._in_title and self.title is not None:
            self.title += data
        if self._script is not None:
            self._script.append(data)
        if not self._invisible:
            self._text.append(data)

    @property
    def visible_text(self) -> str:
        return " ".join("".join(self._text).split())

    def meta(self, key: str) -> str:
        """Content of <meta name=key> or <meta property=key>."""
        for m in self.metas:
            if key in (m.get("name", "").lower(), m.get("property", "").lower()):
                return m.get("content", "").strip()
        return ""

    def http_equiv(self, key: str) -> str:
        for m in self.metas:
            if m.get("http-equiv", "").lower() == key:
                return m.get("content", "").strip()
        return ""

    def has_link(self, rel_token: str) -> bool:
        return any(rel_token in link.get("rel", "").lower().split() for link in self.links)


def parse_html(html: str) -> PageParser:
    parser = PageParser()
    try:
        parser.feed(html)
        parser.close()
    except (AssertionError, ValueError):  # HTMLParser gives up on some broken markup; keep what it read
        pass
    return parser


def looks_like_html(body: bytes) -> bool:
    head = body[:2048].lstrip().lower()
    return head.startswith((b"<!doctype html", b"<html")) or any(t in head for t in (b"<html", b"<head", b"<body"))


def scrub(text: str) -> str:
    """Redact anything secret-shaped before a piece of served text goes into the report."""
    for _, pattern in SECRET_PATTERNS:
        text = pattern.sub(lambda m: redact(m.group(0)), text)
    return JWT.sub(lambda m: redact(m.group(0)), text)


def snippet(text: str, start: int, end: int, width: int = 160) -> str:
    """The match with some context, whitespace collapsed and secrets redacted, at most width chars."""
    pad = max(0, (width - (end - start)) // 2)
    lo, hi = max(0, start - pad), min(len(text), end + pad)
    words = text[lo:hi].split()
    if lo > 0 and len(words) > 1 and not text[lo - 1].isspace():
        words = words[1:]  # drop a word cut in half at the left edge
    if hi < len(text) and len(words) > 1 and not text[hi].isspace():
        words = words[:-1]
    return scrub(" ".join(words))[:width]


# --- One probe run -------------------------------------------------------------

CHUNK_REF = re.compile(
    r"""["'`]((?:/_next/static/|_next/static/|static/chunks/|/assets/|assets/|\./)[A-Za-z0-9_\-./~@%()\[\]]*?\.m?js)(?:\?[^"'`\s]*)?["'`]"""
)
CSP_META = re.compile(r"<meta\b[^>]*http-equiv\s*=\s*[\"']?content-security-policy[^>]*>", re.I)


def chunk_url(ref: str, base: str, site: str) -> str:
    if ref.startswith("/"):
        return site + ref
    if ref.startswith("_next/"):
        return f"{site}/{ref}"
    if ref.startswith("static/chunks/"):
        return f"{site}/_next/{ref}"
    if ref.startswith("assets/"):
        return f"{site}/{ref}"
    return urllib.parse.urljoin(base, ref)


class Probe:
    """State for one run: the page, lazily fetched assets, and the notes to print."""

    def __init__(self, target: str, fetcher: Fetcher, anon_read: bool = False, supabase_url: Optional[str] = None):
        self.target = target
        self.fetcher = fetcher
        self.anon_read = anon_read
        self.supabase_override = supabase_url.rstrip("/") if supabase_url else None
        self.notes: List[str] = []
        self.page = Response(target)
        self.page_url = target
        self.site = origin_url(target)
        self.html = ""
        self.doc = PageParser()
        self._fallback: Optional[Response] = None
        self._js: Optional[Dict[str, str]] = None
        self._css: Dict[str, str] = {}

    def note(self, text: str) -> None:
        if text not in self.notes:
            self.notes.append(text)

    def url(self, path: str) -> str:
        return self.site + path

    def same_origin(self, url: str) -> bool:
        return origin_of(url) == origin_of(self.site)

    def verify(self, rule_id: str) -> str:
        return f"python3 scripts/probe.py --only {rule_id} {self.site}"

    def load(self) -> Optional[str]:
        """Fetch the page. Returns an error message when the site can't be probed at all."""
        url = self.target
        self.fetcher.allow(url)
        resp = self.fetcher.get(url)
        hops = 0
        # Follow http -> https and apex <-> www redirects of the target itself, nothing further.
        while resp.offsite_location and same_site(resp.offsite_location, self.target) and hops < MAX_REDIRECTS:
            url = resp.offsite_location
            self.fetcher.allow(url)
            resp = self.fetcher.get(url)
            hops += 1
        if resp.error:
            return f"could not fetch {resp.url}: {resp.error}"
        if resp.offsite_location:
            return f"{self.target} redirects to {resp.offsite_location}, another site. Probe that URL directly."
        if challenge := bot_challenge(resp):
            return (f"{resp.url} answered with a bot challenge ({challenge}), so every check would describe the "
                    "challenge page instead of the site. Turn the challenge off or allowlist this client, then rerun")
        self.page = resp
        self.page_url = resp.url
        self.site = origin_url(resp.url)
        self.fetcher.allowed["site"] = {origin_of(self.site)}
        if resp.url.rstrip("/") != self.target.rstrip("/"):
            self.note(f"{self.target} redirected to {resp.url}; probed that origin.")
        if self.html_ok:
            self.html = resp.text
            self.doc = parse_html(self.html)
        else:
            self.note(f"The page answered {resp.summary()}, not an HTML page: page-content checks (W08 W09 W15) were skipped.")
        return None

    @property
    def html_ok(self) -> bool:
        return self.page.ok and (looks_like_html(self.page.body) or "html" in self.page.header("content-type"))

    @property
    def html_for_signatures(self) -> str:
        # A CSP meta tag that allowlists a tracker's domain doesn't load it.
        return CSP_META.sub("", self.html)

    @property
    def fallback(self) -> Response:
        """What the site answers for a path that can't exist."""
        if self._fallback is None:
            self._fallback = self.fetcher.get(self.url(NOT_FOUND_PATH), limit=PROBE_BYTES)
        return self._fallback

    def is_fallback(self, resp: Response, path: str) -> bool:
        """True when a 200 is the site's catch-all page rather than a real file at path."""
        if not resp.ok:
            return False
        body = resp.body[:PROBE_BYTES].replace(path.encode(), b"")
        candidates = []
        if self.fallback.ok:
            candidates.append(self.fallback.body[:PROBE_BYTES].replace(NOT_FOUND_PATH.encode(), b""))
        if self.page.ok:
            candidates.append(self.page.body[:PROBE_BYTES])
        return body in candidates

    @property
    def js(self) -> Dict[str, str]:
        if self._js is None:
            self._collect_assets()
        return self._js or {}

    @property
    def css(self) -> Dict[str, str]:
        if self._js is None:
            self._collect_assets()
        return self._css

    def all_texts(self) -> List[Tuple[str, str]]:
        texts = [(self.page_url, self.html)] if self.html else []
        return texts + list(self.js.items()) + list(self.css.items())

    def _collect_assets(self) -> None:
        self._js = {}
        queue: List[str] = []
        styles: List[str] = []
        for s in self.doc.scripts:
            if s.get("src"):
                queue.append(urllib.parse.urljoin(self.page_url, s["src"]))
        for link in self.doc.links:
            rel, href = link.get("rel", "").lower().split(), link.get("href", "")
            if not href:
                continue
            if "modulepreload" in rel or ("preload" in rel and link.get("as", "").lower() == "script"):
                queue.append(urllib.parse.urljoin(self.page_url, href))
            elif "stylesheet" in rel:
                styles.append(urllib.parse.urljoin(self.page_url, href))
        for inline in self.doc.inline_scripts:
            queue += [chunk_url(ref, self.page_url, self.site) for ref in CHUNK_REF.findall(inline)]

        seen, offsite, attempts, truncated = set(), set(), 0, 0
        while queue and attempts < MAX_JS_FILES:
            url = queue.pop(0).split("#")[0]
            if url in seen:
                continue
            seen.add(url)
            if not self.same_origin(url):
                offsite.add(url)
                continue
            attempts += 1
            resp = self.fetcher.get(url)
            if not resp.ok or looks_like_html(resp.body):
                continue
            truncated += len(resp.body) >= MAX_ASSET_BYTES
            self._js[url] = resp.text
            queue += [chunk_url(ref, url, self.site) for ref in CHUNK_REF.findall(resp.text)]
        if queue and attempts >= MAX_JS_FILES:
            self.note(f"Stopped at {MAX_JS_FILES} JS files; later chunks were not read.")

        for url in dict.fromkeys(u.split("#")[0] for u in styles):
            if not self.same_origin(url):
                offsite.add(url)
                continue
            if len(self._css) >= MAX_CSS_FILES:
                break
            resp = self.fetcher.get(url)
            if resp.ok and not looks_like_html(resp.body):
                truncated += len(resp.body) >= MAX_ASSET_BYTES
                self._css[url] = resp.text
        if offsite:
            self.note(f"{len(offsite)} script or stylesheet URL(s) on other origins were not fetched (same origin only).")
        if truncated:
            self.note(f"{truncated} file(s) were larger than {MAX_ASSET_BYTES // (1024 * 1024)} MB; only the first 5 MB was read.")


# --- Rule helpers --------------------------------------------------------------

def make(rule_id: str, where: str, evidence: str, why: str, fix: str, verify: str,
         severity: Optional[str] = None, area: Optional[str] = None, owner: Optional[str] = None) -> Finding:
    rule = RULES_BY_ID[rule_id]
    return Finding(rule_id, severity or rule.severity, area or rule.area, owner or rule.owner,
                   where, evidence, why, fix, verify)


# --- W01 secrets in served files -----------------------------------------------

def check_w01(p: Probe) -> List[Finding]:
    findings = []
    for url, text in p.all_texts():
        by_kind: Dict[str, List[str]] = {}
        for kind, redacted, _ in find_secrets(text):
            by_kind.setdefault(kind, []).append(redacted)
        for kind, values in by_kind.items():
            more = f" and {len(values) - 1} more" if len(values) > 1 else ""
            findings.append(make(
                "W01", url, f"{kind} {values[0]}{more} in the file every visitor downloads",
                "Anyone can open this file in the browser, copy the key, and spend your money or read your data with it.",
                "Move the call that needs this key into a server route or edge function and read the key from a server-only "
                "env var. Then rotate the key in the provider dashboard: removing it from the bundle does not un-leak it.",
                p.verify("W01"),
            ))
    return findings


# --- W02 source maps -----------------------------------------------------------

SOURCEMAP_REF = re.compile(r"[#@]\s*sourceMappingURL=([^\s'\"`*]+)")


def looks_like_sourcemap(resp: Response) -> bool:
    head = resp.body[:PROBE_BYTES]
    return resp.ok and head.lstrip().startswith(b"{") and (b'"sources"' in head or (b'"mappings"' in head and b'"version"' in head))


def check_w02(p: Probe) -> List[Finding]:
    exposed, fetches, guesses = [], 0, 0
    for js_url, text in p.js.items():
        refs = SOURCEMAP_REF.findall(text[-2000:])  # the real comment is at the end; strings elsewhere are code
        if refs and refs[-1].startswith("data:"):
            exposed.append(f"{js_url} (inline map)")
            continue
        if refs:
            map_url = urllib.parse.urljoin(js_url, refs[-1])
            if not p.same_origin(map_url) or fetches >= MAX_MAP_FETCHES:
                continue
            fetches += 1
        elif guesses < MAX_MAP_GUESSES:
            guesses += 1
            map_url = js_url.split("?")[0] + ".map"
        else:
            continue
        if looks_like_sourcemap(p.fetcher.get(map_url, limit=PROBE_BYTES)):
            exposed.append(map_url)
    if not exposed:
        return []
    return [make(
        "W02", exposed[0],
        f"{len(exposed)} source map(s) served as JSON with \"sources\": {', '.join(exposed[:3])}",
        "A source map rebuilds your original source code in the browser's dev tools, comments, "
        "internal routes and all, which makes every other bug easier to find.",
        "Stop publishing maps: `productionBrowserSourceMaps: false` in next.config, or `build.sourcemap: false` in "
        "vite.config. If you need them for error tracking, build with `'hidden'`, upload them to Sentry, and delete "
        "the `.map` files before deploy.",
        f"curl -s -o /dev/null -w '%{{http_code}}\\n' {exposed[0].split(' ')[0]}",
    )]


# --- W03 exposed files ---------------------------------------------------------

ENV_LINE = re.compile(r"^[A-Z_][A-Z0-9_]*=", re.M)


def _not_html(body: bytes) -> bool:
    return not looks_like_html(body) and not body.lstrip().startswith(b"<")


def validate_env(body: bytes) -> Optional[str]:
    n = len(ENV_LINE.findall(body.decode("utf-8", "replace")))
    return f"{n} line(s) shaped like KEY=value, not HTML" if n and _not_html(body) else None


def validate_git_head(body: bytes) -> Optional[str]:
    text = body.decode("utf-8", "replace")
    if text.startswith("ref: refs/") or re.fullmatch(r"[0-9a-f]{40}\s*", text):
        return "body starts with 'ref: refs/' (a git HEAD file)"
    return None


def validate_git_config(body: bytes) -> Optional[str]:
    return "body contains a [core] section (a git config file)" if b"[core]" in body and _not_html(body) else None


def validate_ds_store(body: bytes) -> Optional[str]:
    return "body starts with the DS_Store magic bytes (\\x00\\x00\\x00\\x01Bud1)" if body.startswith(b"\x00\x00\x00\x01Bud1") else None


def validate_zip(body: bytes) -> Optional[str]:
    return "body starts with the ZIP magic bytes (PK\\x03\\x04)" if body.startswith(b"PK\x03\x04") else None


def validate_sql(body: bytes) -> Optional[str]:
    if _not_html(body) and re.search(rb"CREATE TABLE|INSERT INTO", body, re.I):
        return "body contains CREATE TABLE or INSERT INTO, not HTML"
    return None


EXPOSED_FILES = (
    ("/.env", validate_env), ("/.env.local", validate_env), ("/.env.production", validate_env),
    ("/.env.development", validate_env), ("/.git/HEAD", validate_git_head), ("/.git/config", validate_git_config),
    ("/.DS_Store", validate_ds_store), ("/backup.zip", validate_zip), ("/site.zip", validate_zip),
    ("/backup.sql", validate_sql), ("/dump.sql", validate_sql), ("/db.sql", validate_sql), ("/database.sql", validate_sql),
)

EXPOSED_ADVICE = {
    validate_env: (
        "Anyone can download this file and use every key in it: database, payments, email, AI.",
        "Take the file out of the deployed folder (it never belongs in `public/` or the web root) and block dotfiles in "
        "the server config. Then rotate every key it contained.",
    ),
    validate_git_head: (
        "An exposed .git directory lets anyone download your whole source and history, including secrets that were "
        "committed and later deleted.",
        "Deploy the build output, not the repo checkout, or deny `/.git` in the server config (nginx "
        "`location ~ /\\.git { deny all; }`). Rotate any key that was ever committed.",
    ),
    validate_ds_store: (
        "A .DS_Store file lists the names of the files in that folder, which points attackers at backups and private files.",
        "Delete .DS_Store files from the deploy folder, add `.DS_Store` to .gitignore, and deny dotfiles in the server config.",
    ),
    validate_zip: (
        "A downloadable site archive hands over the source code and any keys or config inside it.",
        "Delete the archive from the web root and keep backups in private storage. Rotate any key it contained.",
    ),
    validate_sql: (
        "A public database dump hands every row in it, user records included, to whoever asks for the URL.",
        "Delete the dump from the web root, keep backups in private storage, and treat the data as breached: check "
        "your notification duties and rotate any credentials in it.",
    ),
}
EXPOSED_ADVICE[validate_git_config] = EXPOSED_ADVICE[validate_git_head]


def check_w03(p: Probe) -> List[Finding]:
    findings = []
    for path, validator in EXPOSED_FILES:
        resp = p.fetcher.get(p.url(path), follow=False, limit=PROBE_BYTES)
        if not resp.ok or p.is_fallback(resp, path):
            continue
        matched = validator(resp.body)
        if not matched:
            continue
        why, fix = EXPOSED_ADVICE[validator]
        findings.append(make(
            "W03", p.url(path), f"GET {path} → {resp.status}; validator matched: {matched}. Content not shown.",
            why, fix, f"curl -s -o /dev/null -w '%{{http_code}}\\n' {p.url(path)}",
        ))
    return findings


# --- W04 https -----------------------------------------------------------------

def bare_host(url: str) -> str:
    host = origin_of(url)[1]
    return f"[{host}]" if ":" in host else host


def is_local(url: str) -> bool:
    host = origin_of(url)[1]
    return host in LOCAL_HOSTS or host.endswith(".localhost")


def https_findings(target: str, http_hops: List[Response], https_resp: Optional[Response]) -> Tuple[List[Finding], Optional[str]]:
    """Decide W04 from the http:// redirect chain and, for an http target, the https:// answer."""
    scheme, host = origin_of(target)[0], bare_host(target)
    http_url = f"http://{host}/"
    upgrades = any(r.status in REDIRECT_CODES and r.header("location").lower().startswith("https://") for r in http_hops)
    first = http_hops[0] if http_hops else None
    verify = f"curl -sI {http_url} | grep -iE '^(HTTP|location)'"
    if scheme == "http" and (https_resp is None or https_resp.error):
        reason = https_resp.error if https_resp is not None else "not checked"
        return [make(
            "W04", f"https://{host}/", f"GET https://{host}/ failed: {reason}",
            "Without https, anyone on the same Wi-Fi can read and change the page, including passwords typed into it.",
            "Turn on TLS: your host's managed certificate (Vercel, Netlify and Cloudflare do it for free) or Let's Encrypt "
            "through Caddy or certbot. Then redirect http to https.",
            f"curl -sI https://{host}/ | head -1", severity="P0",
        )], None
    if first is None or first.error:
        return [], f"W04: http://{host}/ did not answer ({first.error if first else 'not checked'}); nothing is served over plain http."
    if upgrades:
        return [], None
    return [make(
        "W04", http_url, f"GET {http_url} → {first.status} with no redirect to https://",
        "Visitors who type the bare domain get a plain-http page anyone on their network can read or rewrite.",
        "Redirect every http request to https with a 301 or 308 (Vercel and Netlify do this by default; nginx: "
        "`return 301 https://$host$request_uri;`), then add Strict-Transport-Security.",
        verify,
    )], None


def check_w04(p: Probe) -> List[Finding]:
    host = bare_host(p.target)
    if is_local(p.target):
        p.note("W04 skipped: localhost has no public https to check.")
        return []
    hops: List[Response] = []
    url = f"http://{host}/"
    for _ in range(3):
        p.fetcher.allow(url)
        resp = p.fetcher.get(url, follow=False, limit=PROBE_BYTES)
        hops.append(resp)
        nxt = urllib.parse.urljoin(url, resp.header("location"))
        if resp.status not in REDIRECT_CODES or not nxt.startswith("http://") or not same_site(nxt, url):
            break
        url = nxt
    https_resp = None
    if origin_of(p.target)[0] == "http":
        p.fetcher.allow(f"https://{host}/")
        https_resp = p.fetcher.get(f"https://{host}/", follow=False, limit=PROBE_BYTES)
    findings, note = https_findings(p.target, hops, https_resp)
    if note:
        p.note(note)
    return findings


# --- W05 security headers ------------------------------------------------------

def header_findings(url: str, headers: Dict[str, str], doc: Optional[PageParser] = None) -> List[Finding]:
    h = {k.lower(): v.strip() for k, v in headers.items()}
    doc = doc or PageParser()
    out = []

    def missing(name: str, why: str, fix: str, severity: str = "P2", evidence: str = "") -> None:
        out.append(make("W05", url, evidence or f"GET {url} → no {name} header", why, fix,
                        f"curl -sI {url} | grep -i {name.split()[0].lower()}", severity=severity))

    if url.lower().startswith("https://"):
        hsts = h.get("strict-transport-security", "")
        age = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
        if not age or int(age.group(1)) == 0:
            missing("Strict-Transport-Security",
                    "Without HSTS, a visitor's first plain-http request can be intercepted and downgraded on hostile Wi-Fi.",
                    "Send `Strict-Transport-Security: max-age=63072000; includeSubDomains` (vercel.json `headers`, "
                    "Netlify `_headers`, or `headers()` in next.config).",
                    evidence=f"GET {url} → Strict-Transport-Security is {'max-age=0' if age else 'missing'}")
    csp = h.get("content-security-policy") or doc.http_equiv("content-security-policy")
    if not csp:
        report_only = bool(h.get("content-security-policy-report-only"))
        missing("Content-Security-Policy",
                "Without an enforced CSP, one XSS bug lets injected script run with full access to the page and its tokens.",
                "Add a Content-Security-Policy starting from `default-src 'self'` plus your real script, style and connect "
                "origins. Ship it as Report-Only for a few days, then enforce it.",
                severity="P3" if report_only else "P2",
                evidence=f"GET {url} → only Content-Security-Policy-Report-Only, nothing enforced" if report_only else "")
    if not h.get("x-frame-options") and "frame-ancestors" not in h.get("content-security-policy", "").lower():
        missing("X-Frame-Options",
                "Another site can load yours in an invisible frame and trick visitors into clicking buttons (clickjacking).",
                "Send `X-Frame-Options: DENY`, or `frame-ancestors 'none'` in the CSP header.",
                evidence=f"GET {url} → no X-Frame-Options and no CSP frame-ancestors")
    if h.get("x-content-type-options", "").lower() != "nosniff":
        missing("X-Content-Type-Options",
                "Browsers may guess a file's type and run an uploaded file as script.",
                "Send `X-Content-Type-Options: nosniff` on every response.",
                evidence=f"GET {url} → X-Content-Type-Options is not nosniff")
    if not h.get("referrer-policy") and not doc.meta("referrer"):
        missing("Referrer-Policy",
                "Full URLs, including tokens or IDs in query strings, leak to every third-party site a visitor clicks to.",
                "Send `Referrer-Policy: strict-origin-when-cross-origin`.", severity="P3")
    if not h.get("permissions-policy") and not h.get("feature-policy"):
        missing("Permissions-Policy",
                "Any embedded script or iframe can ask for camera, microphone or location on your domain's behalf.",
                "Send `Permissions-Policy: camera=(), microphone=(), geolocation=()`, loosened only for features you use.",
                severity="P3")
    return out


def check_w05(p: Probe) -> List[Finding]:
    return header_findings(p.page_url, p.page.headers, p.doc)


# --- W06 version disclosure ----------------------------------------------------

VERSION = re.compile(r"/\s*v?\d+\.\d+")  # nginx/1.18.0, PHP/8.1; not a CDN node tag like ECS (nyb/1D2E)


def version_findings(url: str, headers: Dict[str, str]) -> List[Finding]:
    h = {k.lower(): v.strip() for k, v in headers.items()}
    findings = []
    powered, server = h.get("x-powered-by", ""), h.get("server", "")
    verify = f"curl -sI {url} | grep -iE '^(server|x-powered-by)'"
    fix = ("Next.js: `poweredByHeader: false` in next.config. Express: `app.disable('x-powered-by')`. "
           "nginx: `server_tokens off;`. PHP: `expose_php = Off`.")
    if powered:
        findings.append(make("W06", url, f"X-Powered-By: {powered[:100]}",
                             "It tells attackers which framework to look up known exploits for.", fix, verify))
    if VERSION.search(server):
        findings.append(make("W06", url, f"Server: {server[:100]}",
                             "An exact server version lets attackers match it against published vulnerabilities.", fix, verify))
    return findings


def check_w06(p: Probe) -> List[Finding]:
    return version_findings(p.page_url, p.page.headers)


# --- W07 CORS reflection -------------------------------------------------------

API_PATH = re.compile(r"""["'`](/api/[A-Za-z0-9_\-./]*[A-Za-z0-9_\-])(?=["'`?#])""")
# GET should be safe, but vibecoded APIs often act on GET. Don't touch anything that sounds like it does.
RISKY_API = re.compile(r"(?i)log-?out|sign-?out|delete|remove|destroy|unsubscribe|webhook|cron|reset|revoke|cancel|"
                       r"checkout|pay|send|invite|trigger|purge|admin")


def check_w07(p: Probe) -> List[Finding]:
    paths: List[str] = []
    skipped = 0
    for text in p.js.values():
        for path in API_PATH.findall(text):
            if path in paths:
                continue
            if RISKY_API.search(path):
                skipped += 1
                continue
            paths.append(path)
    if skipped:
        p.note(f"W07: {skipped} /api/ path(s) that sound like they change state were not requested.")
    targets = [p.page_url] + [p.url(path) for path in paths[:MAX_API_PATHS]]
    findings = []
    for url in targets:
        resp = p.fetcher.get(url, headers={"Origin": PROBE_ORIGIN}, limit=PROBE_BYTES)
        if resp.error:
            continue
        acao = resp.header("access-control-allow-origin").strip().lower()
        creds = resp.header("access-control-allow-credentials").strip().lower() == "true"
        is_api = "/api/" in urllib.parse.urlsplit(url).path
        verify = f"curl -s -o /dev/null -D - -H 'Origin: {PROBE_ORIGIN}' {url} | grep -i access-control-allow"
        fix = ("Check the Origin against an explicit allowlist of your own domains (for example `cors({ origin: "
               "['https://yourapp.com'] })`) instead of echoing it back, and never pair an echoed origin with credentials.")
        if acao == PROBE_ORIGIN.lower() and creds:
            findings.append(make(
                "W07", url, f"Origin: {PROBE_ORIGIN} → Access-Control-Allow-Origin echoed back with Access-Control-Allow-Credentials: true",
                "Any website a logged-in visitor opens can call this endpoint with their cookies and read the answer.",
                fix, verify, severity="P0",
            ))
        elif acao == PROBE_ORIGIN.lower():
            findings.append(make(
                "W07", url, f"Origin: {PROBE_ORIGIN} → Access-Control-Allow-Origin echoed back",
                "Any website a visitor opens can call this endpoint from their browser and read the answer.",
                fix, verify,
            ))
        elif acao == "*" and is_api:
            findings.append(make(
                "W07", url, "Access-Control-Allow-Origin: * on an /api/ route",
                "Any website can read this endpoint's responses from a visitor's browser: fine for public data, "
                "a leak for anything per-user.",
                "Replace `*` with your own origins, or drop the CORS headers if only your site calls this route.",
                verify, severity="P2",
            ))
    return findings


# --- W08 page metadata ---------------------------------------------------------

DEFAULT_TITLES = ("vite + react", "vite + react + ts", "vite app", "react app", "create next app", "nuxt", "sveltekit", "astro")
IMAGE_MAGIC = (b"\x00\x00\x01\x00", b"\x89PNG", b"GIF8", b"\xff\xd8\xff", b"RIFF", b"BM")


def is_image(resp: Response) -> bool:
    if not resp.ok or looks_like_html(resp.body):
        return False
    return resp.body.startswith(IMAGE_MAGIC) or resp.header("content-type").lower().startswith("image/")


def check_w08(p: Probe) -> List[Finding]:
    if not p.html_ok:
        return []
    doc, url = p.doc, p.page_url
    findings = []

    def grep(pattern: str) -> str:
        return f"curl -s {url} | grep -ioE '{pattern}'"

    title = " ".join((doc.title or "").split())
    if not title or title.lower() in DEFAULT_TITLES:
        findings.append(make(
            "W08", url, f"<title>{title[:80]}</title> is the scaffold default" if title else "no <title> in the served HTML",
            "Browser tabs, search results and link previews show this title; a default one tells visitors the site isn't finished.",
            "Set a specific title in index.html, or `metadata.title` in the Next.js root layout.",
            grep("<title>[^<]*"),
        ))
    if not doc.meta("description"):
        findings.append(make(
            "W08", url, "no <meta name=\"description\">",
            "Search engines and link previews make up a snippet from whatever text they find first.",
            "Add a one-sentence `<meta name=\"description\" content=\"...\">` (Next.js: `metadata.description`).",
            grep("<meta[^>]+name=.description[^>]*"),
        ))
    if not doc.meta("og:image"):
        findings.append(make(
            "W08", url, "no <meta property=\"og:image\">",
            "Links shared in Slack, iMessage, LinkedIn or X show a bare URL with no picture.",
            "Add a 1200x630 image as `<meta property=\"og:image\" content=\"https://.../og.png\">` "
            "(Next.js: `app/opengraph-image.png`).",
            grep("<meta[^>]+og:image[^>]*"),
        ))
    if not doc.has_link("canonical"):
        findings.append(make(
            "W08", url, "no <link rel=\"canonical\">",
            "Search engines may split ranking between duplicate URLs (www, trailing slash, query strings).",
            "Add `<link rel=\"canonical\" href=\"https://yourdomain/...\">` (Next.js: `metadata.alternates.canonical`).",
            grep("<link[^>]+canonical[^>]*"), severity="P3",
        ))
    if not doc.lang:
        findings.append(make(
            "W08", url, "<html> has no lang attribute" if doc.saw_html else "no <html> tag, so no lang attribute",
            "Screen readers guess the language and mispronounce the page (WCAG 3.1.1), a routine item in accessibility demand letters.",
            "Set `<html lang=\"en\">` (or your language) in index.html or the root layout.",
            grep("<html[^>]*"), area="legal",
        ))
    if doc.h1 != 1:
        findings.append(make(
            "W08", url, f"{doc.h1} <h1> elements in the served HTML",
            "Screen reader users and search engines treat the one H1 as the page's topic; none or several muddles both.",
            "Give each page exactly one H1 with its main heading, and use H2 for the rest.",
            f"curl -s {url} | grep -io '<h1' | wc -l",
        ))
    if not doc.has_link("icon"):
        icon = p.fetcher.get(p.url("/favicon.ico"), limit=PROBE_BYTES)
        if not icon.error and not is_image(icon):
            findings.append(make(
                "W08", url, f"no <link rel=\"icon\"> and GET /favicon.ico → {icon.summary()}, not an image",
                "Tabs and bookmarks show a blank page icon, the first sign of an unfinished site.",
                "Add `app/icon.png` (Next.js) or `public/favicon.ico` plus `<link rel=\"icon\" href=\"/favicon.ico\">`.",
                f"curl -sI {p.url('/favicon.ico')} | grep -i content-type",
            ))
    return findings


# --- W09 client-rendered shell -------------------------------------------------

EMPTY_MOUNT = re.compile(r"<(\w+)\b[^>]*\bid\s*=\s*[\"']?(root|app|__next)[\"']?[^>]*>\s*</\1\s*>", re.I)


def empty_mount(html: str, doc: PageParser) -> Optional[str]:
    """The id of an empty root element when the page is a client-rendered shell, else None."""
    m = EMPTY_MOUNT.search(html)
    return m.group(2) if m and len(doc.visible_text) < 200 else None


def check_w09(p: Probe) -> List[Finding]:
    mount = empty_mount(p.html, p.doc) if p.html_ok else None
    if not mount:
        return []
    return [make(
        "W09", p.page_url,
        f"{len(p.doc.visible_text)} characters of visible text in the served HTML and an empty id=\"{mount}\" mount point",
        "Crawlers, link previews and AI assistants read the HTML before any script runs, so they see an empty page.",
        "Pre-render public pages: SSR or static generation (Next.js, Astro, Nuxt, SvelteKit), or a prerender step "
        "for a Vite SPA (vite-plugin-ssr, react-snap).",
        f"curl -s {p.page_url} | sed -e 's/<[^>]*>//g' | tr -s ' \\n' | wc -c",
    )]


# --- W10 robots, sitemap, llms.txt ---------------------------------------------

AI_CRAWLERS = ("gptbot", "claudebot", "anthropic-ai", "ccbot", "google-extended", "perplexitybot", "applebot-extended")


def robots_groups(text: str) -> List[Dict[str, list]]:
    """Parse robots.txt into groups of user-agents and their Allow/Disallow values."""
    groups: List[Dict[str, list]] = []
    last_was_agent = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        key = key.lower()
        if key == "user-agent":
            if not last_was_agent:
                groups.append({"agents": [], "allow": [], "disallow": []})
            groups[-1]["agents"].append(value.lower())
            last_was_agent = True
        else:
            if key in ("allow", "disallow") and groups:
                groups[-1][key].append(value)
            last_was_agent = False
    return groups


def blocks_all(group: Dict[str, list]) -> bool:
    return "/" in group["disallow"] and "/" not in group["allow"]


def robots_findings(url: str, text: str) -> List[Finding]:
    groups = robots_groups(text)
    verify = f"curl -s {url}"
    if any("*" in g["agents"] and blocks_all(g) for g in groups):
        return [make(
            "W10", url, "User-agent: * with Disallow: /",
            "The whole site is deindexed: search engines drop every page, so nobody finds it.",
            "Change it to `Disallow:` (empty) or list only private paths; for Next.js, fix `app/robots.ts`.",
            verify, severity="P1",
        )]
    blocked = sorted({a for g in groups if blocks_all(g) for a in g["agents"] if a in AI_CRAWLERS})
    if not blocked:
        return []
    return [make(
        "W10", url, f"Disallow: / for {', '.join(blocked)}",
        "AI assistants can't read or cite the site, so it won't show up when people ask them for recommendations.",
        "Confirm this is intended. If not, remove those groups from robots.txt.",
        verify, severity="P3", owner="HUMAN",
    )]


def text_file_present(p: Probe, resp: Response, path: str) -> bool:
    return resp.ok and not looks_like_html(resp.body) and not p.is_fallback(resp, path)


def is_xml_sitemap(p: Probe, resp: Response, path: str) -> bool:
    head = resp.body[:4096].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    xml = head.startswith(b"<?xml") or b"<urlset" in head or b"<sitemapindex" in head
    return resp.ok and xml and b"<html" not in head and not p.is_fallback(resp, path)


def missing_evidence(path: str, resp: Response) -> str:
    if resp.ok:
        return f"GET {path} → {resp.status}, but the body is the site's catch-all HTML page, not the file"
    return f"GET {path} → {resp.summary()}"


def check_w10(p: Probe) -> List[Finding]:
    findings = []
    robots_url = p.url("/robots.txt")
    robots = p.fetcher.get(robots_url, limit=PROBE_BYTES)
    robots_ok = text_file_present(p, robots, "/robots.txt")
    if robots.error:
        p.note(f"W10: /robots.txt could not be fetched ({robots.error}).")
    elif robots_ok:
        findings += robots_findings(robots_url, robots.text)
    else:
        findings.append(make(
            "W10", robots_url, missing_evidence("/robots.txt", robots),
            "Crawlers get no guidance and no sitemap pointer, so new pages are found late or not at all.",
            "Add robots.txt (Next.js: `app/robots.ts`; Vite: `public/robots.txt`) with `User-agent: *`, `Allow: /` "
            "and a `Sitemap:` line.",
            f"curl -s {robots_url}",
        ))

    sitemap_url = p.url("/sitemap.xml")
    sitemap = p.fetcher.get(sitemap_url, limit=PROBE_BYTES)
    present = is_xml_sitemap(p, sitemap, "/sitemap.xml")
    if not present and robots_ok:
        # robots.txt may point somewhere else, such as Astro's /sitemap-index.xml.
        declared = re.findall(r"(?im)^\s*sitemap:\s*(\S+)", robots.text)
        for ref in declared[:2]:
            ref_url = urllib.parse.urljoin(robots_url, ref)
            if not p.same_origin(ref_url):
                present = True
                p.note(f"W10: robots.txt declares a sitemap on another origin ({ref_url}); not fetched.")
                break
            path = urllib.parse.urlsplit(ref_url).path
            if is_xml_sitemap(p, p.fetcher.get(ref_url, limit=PROBE_BYTES), path):
                present = True
                break
    if sitemap.error and not present:
        p.note(f"W10: /sitemap.xml could not be fetched ({sitemap.error}).")
    elif not present:
        findings.append(make(
            "W10", sitemap_url, missing_evidence("/sitemap.xml", sitemap) + " (not an XML sitemap)",
            "Search engines have to discover every page by crawling links, and deep pages may never be indexed.",
            "Generate a sitemap: `app/sitemap.ts` (Next.js), `@astrojs/sitemap`, or `vite-plugin-sitemap`, and list "
            "it in robots.txt.",
            f"curl -s {sitemap_url} | head -c 200",
        ))

    llms_url = p.url("/llms.txt")
    llms = p.fetcher.get(llms_url, limit=PROBE_BYTES)
    if llms.error:
        p.note(f"W10: /llms.txt could not be fetched ({llms.error}).")
    elif not (text_file_present(p, llms, "/llms.txt") and llms.body.strip()):
        findings.append(make(
            "W10", llms_url, missing_evidence("/llms.txt", llms),
            "AI assistants that look for llms.txt get no short, accurate summary of what the site is.",
            "Add `public/llms.txt`: a `# Name` heading, a one-line summary, and links to the key pages in Markdown.",
            f"curl -s {llms_url} | head -5", severity="P3",
        ))
    return findings


# --- W11 404 handling ----------------------------------------------------------

DEFAULT_404_BODIES = (
    ("Next.js default 404", re.compile(r"This page could not be found", re.I)),
    ("nginx default 404", re.compile(r"404 Not Found.*<center>nginx", re.I | re.S)),
    ("Express default 404", re.compile(r"Cannot GET /")),
    ("Vercel default 404", re.compile(r"\bNOT_FOUND\b")),
    ("host default 404", re.compile(r"The page could not be found", re.I)),
)


def not_found_findings(url: str, resp: Response) -> List[Finding]:
    verify = f"curl -s -o /dev/null -w '%{{http_code}}\\n' {url}"
    if resp.ok:
        hop = " (after a redirect)" if resp.redirected else ""
        return [make(
            "W11", url, f"GET {NOT_FOUND_PATH} → {resp.status}{hop} for a path that doesn't exist",
            "Search engines index error pages as real ones (soft 404) and broken links never show up in reports.",
            "Return a real 404 status for unknown paths: render a not-found route (Next.js `app/not-found.tsx`, "
            "`notFound()`), or limit the SPA rewrite to real routes.",
            verify,
        )]
    if resp.status == 404:
        for name, pattern in DEFAULT_404_BODIES:
            if pattern.search(resp.text):
                return [make(
                    "W11", url, f"GET {NOT_FOUND_PATH} → 404 with the {name} page",
                    "Visitors who hit a broken link land on a bare framework page with no way back into the site.",
                    "Add a branded 404 with navigation (Next.js `app/not-found.tsx`, Nuxt `error.vue`, SvelteKit "
                    "`+error.svelte`, or `404.html`).",
                    f"curl -s {url} | head -20", severity="P3", area="design",
                )]
    return []


def check_w11(p: Probe) -> List[Finding]:
    if p.fallback.error:
        p.note(f"W11: {NOT_FOUND_PATH} could not be fetched ({p.fallback.error}).")
        return []
    return not_found_findings(p.url(NOT_FOUND_PATH), p.fallback)


# --- W12 Google Fonts ----------------------------------------------------------

GOOGLE_FONTS = re.compile(r"fonts\.(?:googleapis|gstatic)\.com")


def check_w12(p: Probe) -> List[Finding]:
    findings = []
    sources = ([(p.page_url, p.html_for_signatures, "the served HTML")] if p.html else []) + \
              [(url, text, "a same-origin stylesheet") for url, text in p.css.items()]
    for url, text, label in sources:
        m = GOOGLE_FONTS.search(text)
        if m:
            findings.append(make(
                "W12", url, f"{m.group(0)} in {label}: {snippet(text, m.start(), m.end(), 120)}",
                "Each visitor's IP address goes to Google before any consent; a Munich court awarded €100 to one "
                "visitor for exactly this in 2022.",
                "Self-host the font: `next/font/google` (downloads at build time) or `@fontsource/<family>`, and remove "
                "the fonts.googleapis.com link.",
                f"curl -s {url} | grep -c 'fonts.g'",
            ))
    return findings


# --- W13 trackers without consent ----------------------------------------------

TRACKERS = (
    ("Google Analytics / Tag Manager", re.compile(r"googletagmanager\.com|google-analytics\.com|\bgtag\(|@next/third-parties/google")),
    ("Meta Pixel", re.compile(r"\bfbq\(|connect\.facebook\.net")),
    ("TikTok Pixel", re.compile(r"analytics\.tiktok\.com")),
    ("LinkedIn Insight Tag", re.compile(r"snap\.licdn\.com")),
    ("Mixpanel", re.compile(r"(?i)\bmixpanel\b")),
    # Narrower than the bare words scan.py uses: "amplitude" and "heap" are ordinary identifiers in minified bundles.
    ("Amplitude", re.compile(r"amplitude\.com|@amplitude/|\bamplitude\.(?:init|getInstance)\(")),
    ("Segment", re.compile(r"cdn\.segment\.com|@segment/analytics")),
    ("PostHog", re.compile(r"(?i)\bposthog\b")),
    ("Heap", re.compile(r"heapanalytics\.com|\bheap\.load\(")),
)
REPLAYS = (
    ("Hotjar", re.compile(r"(?i)\bhotjar\b")),
    ("FullStory", re.compile(r"@fullstory|fullstory\.com")),
    ("LogRocket", re.compile(r"(?i)\blogrocket\b")),
    ("Microsoft Clarity", re.compile(r"clarity\.ms")),
    ("Mouseflow", re.compile(r"(?i)\bmouseflow\b")),
    ("Smartlook", re.compile(r"(?i)\bsmartlook\b")),
    ("rrweb recorder", re.compile(r"\brrweb\b")),
    ("Sentry Session Replay", re.compile(r"replayIntegration\)?\s*\(|new Replay\(")),
)
CONSENT = re.compile(
    r"(?i)cookieconsent|\bklaro\b|\bosano\b|onetrust|cookielaw\.org|cookiebot|\btermly\b|iubenda|usercentrics|\bc15t\b|"
    r"gtag\(\s*['\"]consent['\"]|opt_out_capturing_by_default\s*:\s*(?:true|!0)"
)


def tracker_findings(page_url: str, html: str, scripts: Dict[str, str], styles: Dict[str, str], verify: str) -> List[Finding]:
    if any(CONSENT.search(t) for t in [html, *scripts.values(), *styles.values()]):
        return []
    findings = []
    for replay, table in ((False, TRACKERS), (True, REPLAYS)):
        for name, pattern in table:
            in_html = pattern.search(html)
            js_hits = []
            for url, text in scripts.items():
                m = pattern.search(text)
                if m:
                    js_hits.append((url, m))
            if not in_html and not js_hits:
                continue
            if in_html:
                where = page_url
                evidence = f"{name}: `{in_html.group(0)}` in the raw HTML, so it loads before any consent choice"
                if js_hits:
                    evidence += f", and in {len(js_hits)} JS file(s)"
            else:
                where = js_hits[0][0]
                evidence = f"{name}: `{js_hits[0][1].group(0)}` in {len(js_hits)} JS file(s), not in the raw HTML"
            evidence += "; no consent tool found"
            why = ("Session replay records what visitors type and click; without consent that can count as wiretapping "
                   "under California's CIPA (claims of $5,000 per session)." if replay else
                   "Tracking before consent breaks GDPR and ePrivacy rules in the EU and UK, and draws privacy claims in California.")
            fix = (f"Load {name} only after opt-in through a consent tool (vanilla-cookieconsent, Klaro, or your CMP), "
                   "or use Google Consent Mode with everything denied by default. Or switch to cookieless analytics "
                   "(Plausible, Fathom, Vercel Analytics).")
            if replay:
                fix += " Mask every input field in the recorder config."
            findings.append(make("W13", where, evidence, why, fix, verify))
    return findings


def check_w13(p: Probe) -> List[Finding]:
    return tracker_findings(p.page_url, p.html_for_signatures, p.js, p.css, p.verify("W13"))


# --- W14 Supabase anonymous read -----------------------------------------------

SUPABASE_URL = re.compile(r"https://[a-z0-9]{15,30}\.supabase\.co\b")
PUBLISHABLE_KEY = re.compile(r"\bsb_publishable_[A-Za-z0-9_\-]{20,}")
FROM_CALL = re.compile(r"""\.from\(\s*["'`]([A-Za-z_][A-Za-z0-9_]{0,62})["'`]\s*\)""")
REST_LITERAL = re.compile(r"""/rest/v1/([A-Za-z_][A-Za-z0-9_]{0,62})(?=["'`?/])""")


def supabase_config(texts: List[str]) -> Tuple[Optional[str], Optional[str], str]:
    """(project URL, anon key, 'jwt' or 'publishable') found in the served files."""
    url, anon, publishable = None, [], None
    for text in texts:
        m = SUPABASE_URL.search(text)
        url = url or (m.group(0) if m else None)
        anon += [j.group(0) for j in JWT.finditer(text) if jwt_role(j.group(0)) == "anon"]
        m = PUBLISHABLE_KEY.search(text)
        publishable = publishable or (m.group(0) if m else None)
    if anon:
        ref = urllib.parse.urlsplit(url).hostname.split(".")[0] if url else None
        matching = [k for k in anon if (jwt_payload(k) or {}).get("ref") == ref]
        return url, (matching or anon)[0], "jwt"
    return url, publishable, "publishable"


def openapi_tables(resp: Response) -> List[str]:
    try:
        spec = json.loads(resp.body) if resp.ok else {}
    except ValueError:
        return []
    paths = spec.get("paths") if isinstance(spec, dict) else None
    if not isinstance(paths, dict):
        return []
    names = [path.strip("/") for path in paths]
    return [n for n in names if n and "/" not in n]  # "/" is the root, "rpc/..." are functions


def bundle_tables(texts: List[str]) -> List[str]:
    """Table names from `.from('x')` calls and `/rest/v1/x` literals in the served files."""
    names: List[str] = []
    for text in texts:
        for m in FROM_CALL.finditer(text):
            # supabase.storage.from('bucket') names a bucket, and Array.from / Buffer.from aren't queries.
            if text[max(0, m.start() - 8):m.start()].endswith(("storage", "Array", "Buffer")):
                continue
            names.append(m.group(1))
        names += [n for n in REST_LITERAL.findall(text) if n != "rpc"]
    return list(dict.fromkeys(names))


def row_total(content_range: str) -> str:
    m = re.search(r"/\s*(\d+|\*)\s*$", content_range)
    return m.group(1) if m and m.group(1) != "*" else "an unknown number of"


def check_w14(p: Probe) -> List[Finding]:
    texts = [t for _, t in p.all_texts()]
    found_url, key, key_kind = supabase_config(texts)
    if not p.anon_read:
        if found_url:
            p.note("W14 did not run: a Supabase project is referenced in the bundle. Rerun with --anon-read, "
                   "and only against a project you own, to see what the public key can read.")
        return []
    p.note("--anon-read: only run this against a Supabase project you own. It sends GET requests with the public key "
           "the site already ships, never writes, and prints row counts and column names, never values.")
    base = p.supabase_override or found_url
    if not base or not key:
        p.note("W14: no Supabase URL and anon/publishable key found in the served files; nothing to check.")
        return []
    p.fetcher.allow(base, scope="supabase")
    headers = {"apikey": key}
    if key_kind == "jwt":
        headers["Authorization"] = f"Bearer {key}"

    def get(path: str, extra: Optional[Dict[str, str]] = None) -> Response:
        return p.fetcher.get(base + path, headers={**headers, **(extra or {})}, limit=PROBE_BYTES, scope="supabase")

    # Since April 2026 Supabase refuses the OpenAPI listing to anon and publishable keys, so the
    # names the bundle itself uses are the main source. The listing is still tried once.
    from_bundle = bundle_tables(texts)
    root = get("/rest/v1/")
    listed = openapi_tables(root)
    if root.status in (401, 403):
        p.note("W14: the REST schema listing is blocked for anon and publishable keys (Supabase, since April 2026), "
               "so only tables the bundle references were tested. The dashboard's Security Advisor "
               "(or `supabase db advisors`) checks every table.")
    tables = list(dict.fromkeys(listed + from_bundle))
    p.note(f"W14: checked {min(len(tables), MAX_TABLES)} table(s): {len(listed)} from the schema listing, "
           f"{len(from_bundle)} referenced in the bundle.")
    findings = []
    empty = refused = 0
    fix = ("Enable RLS on the table (`alter table public.<t> enable row level security;`) and add policies scoped to "
           "`auth.uid()`. If some columns must be public, expose them through a view with `security_invoker = true`.")
    for table in tables[:MAX_TABLES]:
        path = f"/rest/v1/{urllib.parse.quote(table, safe='')}?select=*&limit=1"
        resp = get(path, {"Prefer": "count=exact", "Range": "0-0", "Range-Unit": "items"})
        try:
            rows = json.loads(resp.body) if resp.status in (200, 206) else None
        except ValueError:
            rows = None
        if not isinstance(rows, list):
            refused += 1
            continue
        if not rows or not isinstance(rows[0], dict):
            empty += 1
            continue
        columns = [str(c)[:40] for c in rows[0]]
        shown = ", ".join(columns[:12]) + (f" and {len(columns) - 12} more" if len(columns) > 12 else "")
        findings.append(make(
            "W14", base + f"/rest/v1/{table}",
            f"anonymous read of {table}: GET {path} with the anon key → {resp.status}, "
            f"{row_total(resp.header('content-range'))} rows readable; columns: {shown} (values not shown)",
            f"Every visitor has the anon key, so anyone can download every row of {table} with one request.",
            fix.replace("<t>", table), f"python3 scripts/probe.py --anon-read --only W14 {p.site}",
        ))
    if empty:
        p.note(f"W14: {empty} table(s) returned no rows to the anon key (RLS on, or the table is empty).")
    if refused:
        p.note(f"W14: {refused} table(s) refused the anon key or don't exist.")

    buckets = get("/storage/v1/bucket")
    try:
        listing = json.loads(buckets.body) if buckets.ok else []
    except ValueError:
        listing = []
    for bucket in listing if isinstance(listing, list) else []:
        if isinstance(bucket, dict) and bucket.get("public") is True:
            name = str(bucket.get("name") or bucket.get("id"))[:60]
            findings.append(make(
                "W14", base + "/storage/v1/bucket", f"storage bucket {name} is public (listed with the anon key)",
                f"Every file in {name} is readable by anyone who has or guesses its URL; one public bucket leaked 13,000 ID documents.",
                f"Make the bucket private (`update storage.buckets set public = false where id = '{name}';`) and serve "
                "files through signed URLs.",
                f"python3 scripts/probe.py --anon-read --only W14 {p.site}", severity="P1",
            ))
    return findings


# --- W15 mixed content ---------------------------------------------------------

def mixed_content_findings(page_url: str, doc: PageParser) -> List[Finding]:
    if not page_url.lower().startswith("https://"):
        return []
    insecure = [(kind, url) for kind, url in doc.resources if url.strip().lower().startswith("http://")]
    if not insecure:
        return []
    listed = ", ".join(f"{kind} {url[:80]}" for kind, url in insecure[:3])
    return [make(
        "W15", page_url, f"{len(insecure)} http:// resource(s) on an https page: {listed}",
        "Browsers block insecure scripts and iframes and flag the page as not secure, so parts of it silently break.",
        "Change those URLs to https:// (or to a path on your own origin).",
        f"curl -s {page_url} | grep -oE '(src|href)=\"http://[^\"]+' | head",
    )]


def check_w15(p: Probe) -> List[Finding]:
    if not p.html_ok:
        return []
    if not p.page_url.lower().startswith("https://"):
        p.note("W15 skipped: the page is plain http, so mixed content doesn't apply.")
        return []
    return mixed_content_findings(p.page_url, p.doc)


# --- W16 directory listing -----------------------------------------------------

LISTING = re.compile(r"Index of /|<title>\s*Directory listing", re.I)


def check_w16(p: Probe) -> List[Finding]:
    findings = []
    for path in ("/assets/", "/static/", "/uploads/", "/files/", "/images/"):
        resp = p.fetcher.get(p.url(path), limit=PROBE_BYTES)
        if resp.ok and not p.is_fallback(resp, path) and LISTING.search(resp.text):
            findings.append(make(
                "W16", p.url(path), f"GET {path} → {resp.status} with a directory index page",
                "Anyone can browse every file in the folder, including uploads and backups that were never linked.",
                "Turn off autoindex (nginx `autoindex off;`, Apache `Options -Indexes`) or add an index file to the folder.",
                f"curl -s {p.url(path)} | grep -i 'index of'",
            ))
    return findings


# --- Registry and CLI ----------------------------------------------------------

@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    area: str
    owner: str
    title: str
    check: Callable[[Probe], List[Finding]]


RULES = [
    Rule("W01", "P0", "secrets", "HUMAN", "Secret in served HTML, JS or CSS", check_w01),
    Rule("W02", "P1", "ops", "AGENT", "Source maps are publicly served", check_w02),
    Rule("W03", "P0", "secrets", "HUMAN", "Exposed .env, .git, backup or SQL dump", check_w03),
    Rule("W04", "P1", "ops", "AGENT", "No http to https redirect, or no https", check_w04),
    Rule("W05", "P2", "ops", "AGENT", "Missing security header", check_w05),
    Rule("W06", "P3", "ops", "AGENT", "Server or framework version disclosed", check_w06),
    Rule("W07", "P1", "ops", "AGENT", "CORS reflects any origin", check_w07),
    Rule("W08", "P2", "seo", "AGENT", "Missing or default page metadata", check_w08),
    Rule("W09", "P2", "seo", "AGENT", "Client-rendered empty shell", check_w09),
    Rule("W10", "P2", "seo", "AGENT", "robots.txt, sitemap.xml or llms.txt problem", check_w10),
    Rule("W11", "P2", "seo", "AGENT", "Soft 404 or framework default 404 page", check_w11),
    Rule("W12", "P1", "legal", "AGENT", "Google Fonts loaded from Google's servers", check_w12),
    Rule("W13", "P1", "legal", "AGENT", "Tracker or session replay with no consent tool", check_w13),
    Rule("W14", "P0", "data", "HUMAN", "Supabase data readable with the anon key", check_w14),
    Rule("W15", "P2", "ops", "AGENT", "Mixed content on an https page", check_w15),
    Rule("W16", "P1", "ops", "AGENT", "Directory listing enabled", check_w16),
]
RULES_BY_ID = {r.id: r for r in RULES}


def select_rules(only: Optional[str]) -> List[Rule]:
    if not only:
        return list(RULES)
    wanted = [t.strip() for t in only.split(",") if t.strip()]
    unknown = [t for t in wanted if t.upper() not in RULES_BY_ID and t.lower() not in AREAS]
    if unknown:
        raise ValueError(f"unknown rule or area in --only: {', '.join(unknown)}")
    ids = {t.upper() for t in wanted}
    areas = {t.lower() for t in wanted}
    return [r for r in RULES if r.id in ids or r.area in areas]


def normalize_target(url: str) -> str:
    if "://" not in url:
        url = "https://" + url
    parts = urllib.parse.urlsplit(url)
    if parts.scheme.lower() not in DEFAULT_PORTS or not parts.hostname:
        raise ValueError(f"not an http(s) URL: {url}")
    _ = parts.port  # raises ValueError on a malformed port
    return urllib.parse.urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "/", parts.query, ""))


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only live probe of a deployed site (rules W01-W16).")
    parser.add_argument("url", nargs="?", help="the page to probe, e.g. https://staging.example.app")
    parser.add_argument("--anon-read", action="store_true",
                        help="W14: read Supabase tables with the site's public key. Only against a project you own.")
    parser.add_argument("--timeout", type=float, default=10.0, help="seconds per request (default 10)")
    parser.add_argument("--max-requests", type=int, default=150, help="hard cap on total requests (default 150)")
    parser.add_argument("--only", help="comma-separated rule IDs or areas, e.g. W03,W14 or secrets,seo")
    parser.add_argument("--supabase-url", help=argparse.SUPPRESS)  # tests point W14 at a local fake
    add_output_args(parser)
    args = parser.parse_args(argv)

    if args.list_rules:
        emit(rules_table(RULES, args.format), args.out)
        return 0
    if not args.url:
        parser.error("a URL is required (or --list-rules)")
    if args.timeout <= 0 or args.max_requests < 1:
        parser.error("--timeout and --max-requests must be positive")
    try:
        target = normalize_target(args.url)
        rules = select_rules(args.only)
    except ValueError as e:
        parser.error(str(e))

    fetcher = Fetcher(args.timeout, args.max_requests)
    probe = Probe(target, fetcher, anon_read=args.anon_read, supabase_url=args.supabase_url)
    error = probe.load()
    if error:
        try:
            emit(render(TOOL, target, [], args.format, [f"Probe aborted, no checks ran: {error}."]), args.out)
        except OSError as e:
            print(f"probe.py: cannot write report: {e}", file=sys.stderr)
        print(f"probe.py: {error}", file=sys.stderr)
        return 2

    findings: List[Finding] = []
    for rule in rules:
        try:
            findings += rule.check(probe)
        except Exception as e:  # one broken check must not cost the whole report
            probe.note(f"{rule.id} stopped on an internal error ({type(e).__name__}: {e}); its results are incomplete.")
    probe.note(f"{fetcher.count} request(s) sent, all GET (cap {fetcher.max_requests}).")
    if fetcher.cap_hit:
        probe.note(f"Request cap of {fetcher.max_requests} reached, so some checks are incomplete. Rerun with a higher --max-requests.")
    if fetcher.failed:
        probe.note(f"{fetcher.failed} request(s) failed (timeouts or connection errors); those checks did not fire.")
    if fetcher.failed_in_a_row >= MAX_CONSECUTIVE_FAILURES:
        probe.note(f"Stopped sending after {MAX_CONSECUTIVE_FAILURES} failures in a row; the site may be down or rate-limiting.")
    try:
        emit(render(TOOL, probe.page_url, findings, args.format, probe.notes), args.out)
    except OSError as e:
        print(f"probe.py: cannot write report: {e}", file=sys.stderr)
        return 2
    return exit_code(findings, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())
