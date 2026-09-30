"""Tests for probe.py. Every server here binds 127.0.0.1:0; nothing touches the real network.

A bad site trips every rule a local http server can show, a good site must produce zero
findings, and an SPA site that answers 200 index.html for every path must not fool the
exposed-file and robots/sitemap checks. W04 and the https-only parts of W05 and W15 are
tested through their decision functions with fake responses.
"""

import base64
import contextlib
import io
import json
import socket
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import probe  # noqa: E402


# --- Fixture data --------------------------------------------------------------

def b64url(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")


def make_jwt(role: str, ref: str = "abcdefghijklmnopqrst") -> str:
    payload = {"iss": "supabase", "ref": ref, "role": role, "iat": 1700000000, "exp": 2000000000}
    return f"{b64url({'alg': 'HS256', 'typ': 'JWT'})}.{b64url(payload)}.c2lnbmF0dXJlLWJ5dGVzLWhlcmU"


# Built at runtime so a secret scanner reading this file finds nothing to report.
ANON_KEY = make_jwt("anon")
SERVICE_KEY = make_jwt("service_role")
STRIPE_SECRET = "sk_" + "live_" + "Zq8Lw2Rt" * 3
ENV_CANARY = "env-canary-value-93f1"
ROW_VALUES = ("alice.w@canary-mail.test", "078-05-1120", "Alice Wonder")

HTML = {"Content-Type": "text/html; charset=utf-8"}
JS = {"Content-Type": "application/javascript"}
CSS = {"Content-Type": "text/css"}
JSON_TYPE = {"Content-Type": "application/json"}
TEXT = {"Content-Type": "text/plain"}

GOOD_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}

GOOD_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Tidewater Bakery | Sourdough baked daily in Portland</title>
  <meta name="description" content="Naturally leavened bread and pastries, baked every morning in Portland. Order ahead for pickup.">
  <meta property="og:image" content="https://tidewater.test/og.png">
  <link rel="canonical" href="https://tidewater.test/">
  <link rel="icon" href="/favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="/assets/site-7c1d.css">
  <link rel="modulepreload" href="/assets/About-d4e5f6.js">
  <script type="module" src="/assets/index-a1b2c3.js"></script>
  <script defer data-domain="tidewater.test" src="https://cdn.invalid/plausible/script.js"></script>
  <script type="application/ld+json">{"@context":"https://schema.org","@type":"Bakery","name":"Tidewater Bakery"}</script>
</head>
<body>
  <header><a href="/">Tidewater Bakery</a> <a href="/menu">Menu</a> <a href="https://www.instagram.com/tidewater">Instagram</a></header>
  <main>
    <h1>Bread worth the wait</h1>
    <p>We mix the dough the night before and let it rise slowly for eighteen hours. That long, cool
    fermentation gives the crust its crackle and the crumb its tang. Every loaf is shaped by hand.</p>
    <p>Open Wednesday to Sunday, 7am until we sell out. Order by 6pm for next-morning pickup at
    1120 SE Water Street.</p>
    <img src="/images/country-loaf.jpg" alt="A country loaf on a cooling rack" width="800" height="600">
  </main>
  <footer><a href="/privacy">Privacy</a> <a href="/terms">Terms</a></footer>
</body>
</html>
"""

GOOD_JS = (
    'const supabaseUrl="https://abcdefghijklmnopqrst.supabase.co",supabaseKey="' + ANON_KEY + '";'
    'const stripeKey="pk_live_51HqLyjWDarjtT1zdp7dcXyZ";'  # publishable: meant for browsers
    'export async function menu(){const r=await fetch("/api/menu");return r.json()}'
    'export const items=()=>client.from("menu_items").select("id,name");'
    'export const avatar=n=>client.storage.from("avatars").getPublicUrl(n);'
    'const About=()=>import("./About-d4e5f6.js");\n'
)

GOOD_404 = ("<!doctype html><html lang=\"en\"><head><title>Not found | Tidewater Bakery</title></head>"
            "<body><h1>We couldn't find that page</h1><a href=\"/\">Back to the bakery</a></body></html>")


def good_routes():
    return {
        "/": (200, HTML, GOOD_HTML),
        "/assets/index-a1b2c3.js": (200, JS, GOOD_JS),
        "/assets/About-d4e5f6.js": (200, JS, 'export default function About(){return"Baked in Portland since 2019"}\n'),
        "/assets/site-7c1d.css": (200, CSS, '@font-face{font-family:"Fraunces";src:url(/fonts/fraunces.woff2) format("woff2")}'
                                            'body{font-family:"Fraunces",Georgia,serif}a:focus-visible{outline:2px solid #1d4ed8}\n'),
        "/robots.txt": (200, TEXT, "User-agent: *\nAllow: /\nDisallow: /admin\n\nSitemap: https://tidewater.test/sitemap.xml\n"),
        "/sitemap.xml": (200, {"Content-Type": "application/xml"},
                         '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                         "<url><loc>https://tidewater.test/</loc></url></urlset>\n"),
        "/llms.txt": (200, TEXT, "# Tidewater Bakery\n\n> Sourdough bakery in Portland, Oregon.\n\n- [Menu](https://tidewater.test/menu)\n"),
        "/favicon.svg": (200, {"Content-Type": "image/svg+xml"}, '<svg xmlns="http://www.w3.org/2000/svg"/>'),
        "/api/menu": (200, JSON_TYPE, '{"items":[]}'),
    }


BAD_HTML = """<!DOCTYPE html>
<html>
<head>
<title>Vite + React</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;700">
<link rel="stylesheet" href="/assets/index-bad.css">
<script async src="https://www.googletagmanager.com/gtag/js?id=G-ABC123"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments)}gtag('js',new Date());gtag('config','G-ABC123');</script>
<script>window.__CONFIG__={serviceKey:"%s"}</script>
<script type="module" crossorigin src="/assets/index-bad.js"></script>
</head>
<body><div id="root"></div><noscript>You need to enable JavaScript to run this app.</noscript></body>
</html>
""" % SERVICE_KEY

BAD_JS = (
    'const stripe="' + STRIPE_SECRET + '";'
    'export const me=()=>fetch("/api/user",{credentials:"include"});'
    'export const stats=()=>fetch("/api/public");'
    'export const bye=()=>fetch("/api/logout");\n'
    "//# sourceMappingURL=index-bad.js.map\n"
)


def reflect_origin(body, content_type=HTML, credentials=False):
    """A route that echoes the request's Origin back, the classic CORS misconfiguration."""
    def route(handler):
        headers = dict(content_type)
        origin = handler.headers.get("Origin")
        if origin:
            headers["Access-Control-Allow-Origin"] = origin
            if credentials:
                headers["Access-Control-Allow-Credentials"] = "true"
        return 200, headers, body
    return route


def bad_routes():
    return {
        "/": reflect_origin(BAD_HTML),
        "/assets/index-bad.js": (200, JS, BAD_JS),
        "/assets/index-bad.js.map": (200, JSON_TYPE, '{"version":3,"sources":["../src/App.tsx"],"mappings":"AAAA"}'),
        "/assets/index-bad.css": (200, CSS, '@import url("https://fonts.googleapis.com/css2?family=Roboto");body{margin:0}\n'),
        "/.env": (200, TEXT, f"NODE_ENV=production\nSESSION_SECRET={ENV_CANARY}\n"),
        "/.git/HEAD": (200, TEXT, "ref: refs/heads/main\n"),
        "/.git/config": (200, TEXT, "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"),
        "/.DS_Store": (200, {"Content-Type": "application/octet-stream"}, b"\x00\x00\x00\x01Bud1" + b"\x00" * 32),
        "/backup.zip": (200, {"Content-Type": "application/zip"}, b"PK\x03\x04\x14\x00" + b"\x00" * 24),
        "/dump.sql": (200, TEXT, "CREATE TABLE users (id int, email text);\nINSERT INTO users VALUES (1, 'x');\n"),
        "/robots.txt": (200, TEXT, "User-agent: *\nDisallow: /\n"),
        "/uploads/": (200, HTML, "<html><head><title>Index of /uploads/</title></head><body><h1>Index of /uploads/</h1>"
                                 "<a href=\"id-scan.jpg\">id-scan.jpg</a></body></html>"),
        "/api/user": reflect_origin('{"id":1}', JSON_TYPE, credentials=True),
        "/api/public": (200, {**JSON_TYPE, "Access-Control-Allow-Origin": "*"}, '{"visits":10}'),
        "/api/logout": (200, JSON_TYPE, '{"ok":true}'),
    }


SPA_HTML = GOOD_HTML.replace('<script type="module" src="/assets/index-a1b2c3.js"></script>',
                             '<script type="module" src="/assets/app-9f8e7d.js"></script>')
SPA_JS = 'export const list=()=>fetch("/api/items");\n'


def spa_routes():
    return {"/assets/app-9f8e7d.js": (200, JS, SPA_JS)}


def spa_fallback(handler):
    # Like an SSR host, the catch-all page embeds the requested path, so bodies differ per URL.
    page = SPA_HTML.replace("</body>", f'<script>window.__ROUTE__="{urlsplit(handler.path).path}"</script></body>')
    return 200, HTML, page


# --- Local servers -------------------------------------------------------------

class Site:
    """A server on 127.0.0.1:0 that serves routes from a dict and records every request."""

    def __init__(self, routes, default=None, server_header="cloudflare", headers=None):
        self.routes = routes
        self.default = default or (404, HTML, "<html><body>Not found</body></html>")
        self.server_header = server_header
        self.common_headers = headers or {}
        self.requests = []  # (method, path, lower-cased headers)

    def __enter__(self):
        site = self

        class Handler(BaseHTTPRequestHandler):
            def version_string(self):
                return site.server_header

            def log_message(self, *args):
                pass

            def do_GET(self):
                site.serve(self)

            def refuse(self):
                site.requests.append((self.command, self.path, {k.lower(): v for k, v in self.headers.items()}))
                self.send_response(405)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_HEAD = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = refuse

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    def serve(self, handler):
        self.requests.append(("GET", handler.path, {k.lower(): v for k, v in handler.headers.items()}))
        route = self.routes.get(urlsplit(handler.path).path, self.default)
        status, headers, body = route(handler) if callable(route) else route
        body = body.encode() if isinstance(body, str) else body
        handler.send_response(status)
        for name, value in {**self.common_headers, **headers}.items():
            handler.send_header(name, value)
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    def paths(self):
        return [urlsplit(path).path for _, path, _ in self.requests]


def supabase_routes(listing_blocked=False):
    rows = [{"id": 7, "email": ROW_VALUES[0], "ssn": ROW_VALUES[1], "full_name": ROW_VALUES[2]}]
    openapi = {"swagger": "2.0", "paths": {"/": {}, "/profiles": {}, "/notes": {}, "/rpc/delete_everything": {}}}
    return {
        "/rest/v1/": (401, JSON_TYPE, '{"message":"schema listing requires a secret key"}') if listing_blocked
        else (200, {"Content-Type": "application/openapi+json"}, json.dumps(openapi)),
        "/rest/v1/profiles": (206, {**JSON_TYPE, "Content-Range": "0-0/42"}, json.dumps(rows)),
        "/rest/v1/menu_items": (200, {**JSON_TYPE, "Content-Range": "0-0/12"},
                                json.dumps([{"id": 1, "name": ROW_VALUES[2], "price_cents": 900}])),
        "/rest/v1/notes": (200, {**JSON_TYPE, "Content-Range": "*/0"}, "[]"),
        "/storage/v1/bucket": (200, JSON_TYPE, json.dumps([
            {"id": "avatars", "name": "avatars", "public": True},
            {"id": "invoices", "name": "invoices", "public": False},
        ])),
    }


def rls_on_routes():
    openapi = {"swagger": "2.0", "paths": {"/": {}, "/menu_items": {}, "/orders": {}}}
    return {
        "/rest/v1/": (200, {"Content-Type": "application/openapi+json"}, json.dumps(openapi)),
        "/rest/v1/menu_items": (200, {**JSON_TYPE, "Content-Range": "*/0"}, "[]"),
        "/rest/v1/orders": (200, {**JSON_TYPE, "Content-Range": "*/0"}, "[]"),
        "/storage/v1/bucket": (200, JSON_TYPE, "[]"),
    }


def run_probe(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = probe.main(["--timeout", "3", *args])
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


def run_json(*args):
    code, out, err = run_probe(*args, "--format", "json")
    return code, json.loads(out)


def of(report, rule_id):
    return [f for f in report["findings"] if f["id"] == rule_id]


def fake(url, status=200, headers=None, body=b"", error=""):
    return probe.Response(url, status, {k.lower(): v for k, v in (headers or {}).items()}, body, error)


# --- Registry ------------------------------------------------------------------

EXPECTED_RULES = {
    "W01": ("P0", "secrets", "HUMAN"), "W02": ("P1", "ops", "AGENT"), "W03": ("P0", "secrets", "HUMAN"),
    "W04": ("P1", "ops", "AGENT"), "W05": ("P2", "ops", "AGENT"), "W06": ("P3", "ops", "AGENT"),
    "W07": ("P1", "ops", "AGENT"), "W08": ("P2", "seo", "AGENT"), "W09": ("P2", "seo", "AGENT"),
    "W10": ("P2", "seo", "AGENT"), "W11": ("P2", "seo", "AGENT"), "W12": ("P1", "legal", "AGENT"),
    "W13": ("P1", "legal", "AGENT"), "W14": ("P0", "data", "HUMAN"), "W15": ("P2", "ops", "AGENT"),
    "W16": ("P1", "ops", "AGENT"),
}


class RegistryTests(unittest.TestCase):
    def test_rules_match_the_spec_table(self):
        got = {r.id: (r.severity, r.area, r.owner) for r in probe.RULES}
        self.assertEqual(got, EXPECTED_RULES)
        for rule in probe.RULES:
            self.assertTrue(0 < len(rule.title) < 60, rule.title)

    def test_list_rules_md_and_json(self):
        result = subprocess.run([sys.executable, str(HERE / "probe.py"), "--list-rules"], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0)
        for rule_id in EXPECTED_RULES:
            self.assertIn(f"| {rule_id} |", result.stdout)
        code, out, _ = run_probe("--list-rules", "--format", "json")
        self.assertEqual(code, 0)
        self.assertEqual([r["id"] for r in json.loads(out)], list(EXPECTED_RULES))

    def test_only_accepts_ids_and_areas(self):
        self.assertEqual([r.id for r in probe.select_rules("W03,seo")], ["W03", "W08", "W09", "W10", "W11"])
        with self.assertRaises(ValueError):
            probe.select_rules("W99")
        code, _, err = run_probe("http://127.0.0.1:9/", "--only", "W99")
        self.assertEqual(code, 2)
        self.assertIn("unknown rule", err)


# --- Bad site: every rule a local server can show ------------------------------

class BadSiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.site = Site(bad_routes(), default=(200, HTML, BAD_HTML), server_header="nginx/1.18.0",
                        headers={"X-Powered-By": "Express"}).__enter__()
        cls.code, cls.report = run_json(cls.site.url + "/")
        cls.md_code, cls.md, _ = run_probe(cls.site.url + "/")

    @classmethod
    def tearDownClass(cls):
        cls.site.__exit__(None, None, None)

    def test_bad_site_fails_the_gate_and_prints_valid_output(self):
        self.assertEqual(self.code, 1)
        self.assertEqual(self.md_code, 1)
        self.assertEqual(self.report["tool"], "probe.py")
        self.assertFalse([n for n in self.report["notes"] if "internal error" in n], self.report["notes"])
        self.assertIn("### W03 · P0 · secrets · HUMAN", self.md)
        fired = {f["id"] for f in self.report["findings"]}
        self.assertEqual(fired, set(EXPECTED_RULES) - {"W04", "W14", "W15"})

    def test_bad_site_is_probed_politely(self):
        self.assertEqual({method for method, _, _ in self.site.requests}, {"GET"})
        self.assertNotIn("/api/logout", self.site.paths())
        self.assertTrue(all(h.get("user-agent") == probe.USER_AGENT for _, _, h in self.site.requests))

    def test_bad_site_never_prints_a_secret(self):
        for output in (self.md, json.dumps(self.report)):
            for secret in (STRIPE_SECRET, SERVICE_KEY, ENV_CANARY, "../src/App.tsx"):
                self.assertNotIn(secret, output)

    def test_W01_secret_in_bundle_and_inline_html(self):
        self.assertEqual(len(of(self.report, "W01")), 2)
        kinds = " ".join(f["evidence"] for f in of(self.report, "W01"))
        self.assertIn("stripe secret key", kinds)
        self.assertIn("Supabase service_role JWT", kinds)
        where = {f["where"] for f in of(self.report, "W01")}
        self.assertEqual(where, {self.site.url + "/", self.site.url + "/assets/index-bad.js"})
        self.assertTrue(all(f["severity"] == "P0" and "rotate" in f["fix"] for f in of(self.report, "W01")))

    def test_W02_source_map_served(self):
        (finding,) = of(self.report, "W02")
        self.assertIn("/assets/index-bad.js.map", finding["evidence"])
        self.assertIn("1 source map", finding["evidence"])

    def test_W03_exposed_files_are_content_validated(self):
        paths = sorted(urlsplit(f["where"]).path for f in of(self.report, "W03"))
        # The bad site answers 200 HTML for every other path, and none of those may count.
        self.assertEqual(paths, ["/.DS_Store", "/.env", "/.git/HEAD", "/.git/config", "/backup.zip", "/dump.sql"])
        for f in of(self.report, "W03"):
            self.assertIn("validator matched", f["evidence"])
            self.assertIn("Content not shown", f["evidence"])

    def test_W05_missing_headers_on_http(self):
        got = sorted((f["severity"], f["evidence"]) for f in of(self.report, "W05"))
        self.assertEqual([s for s, _ in got], ["P2", "P2", "P2", "P3", "P3"])
        text = " ".join(e for _, e in got)
        for name in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"):
            self.assertIn(name, text)
        self.assertNotIn("Strict-Transport-Security", text)  # https only

    def test_W06_version_headers(self):
        evidence = sorted(f["evidence"] for f in of(self.report, "W06"))
        self.assertEqual(evidence, ["Server: nginx/1.18.0", "X-Powered-By: Express"])

    def test_W07_cors_reflection_levels(self):
        got = {urlsplit(f["where"]).path: f["severity"] for f in of(self.report, "W07")}
        self.assertEqual(got, {"/": "P1", "/api/user": "P0", "/api/public": "P2"})
        origin_requests = [h for _, _, h in self.site.requests if "origin" in h]
        self.assertTrue(origin_requests and all(h["origin"] == probe.PROBE_ORIGIN for h in origin_requests))

    def test_W08_metadata_each_missing_item(self):
        items = of(self.report, "W08")
        text = " | ".join(f["evidence"] for f in items)
        for piece in ("Vite + React", "description", "og:image", "canonical", "lang", "0 <h1>", "favicon.ico"):
            self.assertIn(piece, text)
        self.assertEqual(len(items), 7)
        lang = [f for f in items if "lang" in f["evidence"]]
        self.assertEqual((lang[0]["area"], lang[0]["severity"]), ("legal", "P2"))
        canonical = [f for f in items if "canonical" in f["evidence"]]
        self.assertEqual(canonical[0]["severity"], "P3")

    def test_W09_empty_client_shell(self):
        (finding,) = of(self.report, "W09")
        self.assertIn('id="root"', finding["evidence"])

    def test_W10_robots_blocks_everything_and_files_missing(self):
        got = {urlsplit(f["where"]).path: f["severity"] for f in of(self.report, "W10")}
        self.assertEqual(got, {"/robots.txt": "P1", "/sitemap.xml": "P2", "/llms.txt": "P3"})
        sitemap = [f for f in of(self.report, "W10") if f["where"].endswith("/sitemap.xml")][0]
        self.assertIn("catch-all", sitemap["evidence"])

    def test_W11_soft_404(self):
        (finding,) = of(self.report, "W11")
        self.assertEqual(finding["severity"], "P2")
        self.assertIn("→ 200", finding["evidence"])

    def test_W12_google_fonts_in_html_and_stylesheet(self):
        where = sorted(f["where"] for f in of(self.report, "W12"))
        self.assertEqual(where, [self.site.url + "/", self.site.url + "/assets/index-bad.css"])

    def test_W13_tracker_in_raw_html_without_consent(self):
        (finding,) = of(self.report, "W13")
        self.assertIn("Google Analytics", finding["evidence"])
        self.assertIn("raw HTML", finding["evidence"])

    def test_W16_directory_listing(self):
        (finding,) = of(self.report, "W16")
        self.assertTrue(finding["where"].endswith("/uploads/"))


# --- Good site: the false-positive guard ---------------------------------------

class GoodSiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.site = Site(good_routes(), default=(404, HTML, GOOD_404), headers=GOOD_HEADERS).__enter__()
        cls.code, cls.report = run_json(cls.site.url)
        cls.md_code, cls.md, _ = run_probe(cls.site.url)

    @classmethod
    def tearDownClass(cls):
        cls.site.__exit__(None, None, None)

    def test_good_site_has_zero_findings(self):
        self.assertEqual(self.report["findings"], [], json.dumps(self.report["findings"], indent=1, ensure_ascii=False))
        self.assertEqual(self.code, 0)
        self.assertEqual(self.md_code, 0)
        self.assertIn("0 findings", self.md)
        self.assertFalse([n for n in self.report["notes"] if "internal error" in n], self.report["notes"])

    def test_good_site_notes_explain_what_was_skipped(self):
        notes = " ".join(self.report["notes"])
        self.assertIn("W04 skipped", notes)
        self.assertIn("W15 skipped", notes)
        self.assertIn("--anon-read", notes)  # Supabase is referenced, W14 did not run
        self.assertIn("other origins were not fetched", notes)

    def test_good_site_fetches_bundles_and_stays_on_origin(self):
        paths = self.site.paths()
        self.assertIn("/assets/index-a1b2c3.js", paths)
        self.assertIn("/assets/About-d4e5f6.js", paths)
        self.assertEqual({m for m, _, _ in self.site.requests}, {"GET"})
        self.assertLessEqual(len(self.site.requests), 2 * 40)  # two runs, md and json
        self.assertNotIn(ANON_KEY, self.md)


# --- SPA fallback: 200 index.html for every path -------------------------------

class SpaFallbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.site = Site(spa_routes(), default=spa_fallback, server_header="Netlify", headers=GOOD_HEADERS).__enter__()
        cls.code, cls.report = run_json(cls.site.url)

    @classmethod
    def tearDownClass(cls):
        cls.site.__exit__(None, None, None)

    def test_W03_spa_fallback_is_not_an_exposed_file(self):
        self.assertEqual(of(self.report, "W03"), [])
        self.assertIn("/.env", self.site.paths())  # it did look

    def test_W10_spa_fallback_counts_as_missing(self):
        items = of(self.report, "W10")
        got = {urlsplit(f["where"]).path: f["severity"] for f in items}
        self.assertEqual(got, {"/robots.txt": "P2", "/sitemap.xml": "P2", "/llms.txt": "P3"})
        self.assertTrue(all("catch-all" in f["evidence"] for f in items))

    def test_W11_spa_fallback_is_a_soft_404(self):
        self.assertEqual([f["severity"] for f in of(self.report, "W11")], ["P2"])

    def test_spa_fallback_fools_nothing_else(self):
        fired = sorted(f["id"] for f in self.report["findings"])
        self.assertEqual(fired, ["W10", "W10", "W10", "W11"], json.dumps(self.report["findings"], indent=1))


class PlainTextFallbackTests(unittest.TestCase):
    def test_W10_text_fallback_is_not_a_robots_file(self):
        with Site({}, default=(200, TEXT, "ok"), headers=GOOD_HEADERS) as site:
            _, report = run_json(site.url, "--only", "W03,W10,W16")
        got = {urlsplit(f["where"]).path for f in of(report, "W10")}
        self.assertEqual(got, {"/robots.txt", "/sitemap.xml", "/llms.txt"})
        self.assertEqual(of(report, "W03") + of(report, "W16"), [])


# --- W14: Supabase anonymous read against a fake PostgREST ---------------------

class SupabaseTests(unittest.TestCase):
    def run_anon(self, supabase, *extra):
        with Site(good_routes(), default=(404, HTML, GOOD_404), headers=GOOD_HEADERS) as site:
            code, report = run_json(site.url, "--anon-read", "--supabase-url", supabase.url, *extra)
            _, md, _ = run_probe(site.url, "--anon-read", "--supabase-url", supabase.url, *extra)
        return code, report, md

    def test_W14_openapi_listing_reads_rows_without_printing_values(self):
        with Site(supabase_routes()) as supabase:
            code, report, md = self.run_anon(supabase, "--only", "W14")
        self.assertEqual(code, 1)
        tables = {f["where"].rsplit("/", 1)[-1]: f for f in of(report, "W14") if "/rest/v1/" in f["where"]}
        self.assertEqual(set(tables), {"profiles", "menu_items"})  # listed + referenced in the bundle
        profiles = tables["profiles"]
        self.assertEqual(profiles["severity"], "P0")
        self.assertIn("anonymous read of profiles", profiles["evidence"])
        self.assertIn("42 rows", profiles["evidence"])
        self.assertIn("email, ssn, full_name", profiles["evidence"])
        buckets = [f for f in of(report, "W14") if f["where"].endswith("/storage/v1/bucket")]
        self.assertEqual([(f["severity"], "avatars" in f["evidence"]) for f in buckets], [("P1", True)])
        for output in (md, json.dumps(report)):
            for value in ROW_VALUES + (ANON_KEY,):
                self.assertNotIn(value, output)
        self.assertEqual({m for m, _, _ in supabase.requests}, {"GET"})
        self.assertFalse([p for p in supabase.paths() if "/rpc/" in p])
        self.assertTrue(all(h.get("apikey") == ANON_KEY and h.get("authorization") == f"Bearer {ANON_KEY}"
                            for _, _, h in supabase.requests))
        table_reads = [h for _, path, h in supabase.requests if path.startswith("/rest/v1/profiles")]
        self.assertEqual(table_reads[0].get("prefer"), "count=exact")
        self.assertEqual(table_reads[0].get("range"), "0-0")
        self.assertIn("only run this against a Supabase project you own", " ".join(report["notes"]))

    def test_W14_listing_blocked_falls_back_to_bundle_names(self):
        with Site(supabase_routes(listing_blocked=True)) as supabase:
            _, report, md = self.run_anon(supabase, "--only", "W14")
        tables = [f["where"].rsplit("/", 1)[-1] for f in of(report, "W14") if "/rest/v1/" in f["where"]]
        self.assertEqual(tables, ["menu_items"])
        self.assertNotIn("/rest/v1/profiles", supabase.paths())  # only the listing named it
        self.assertNotIn("/rest/v1/avatars", supabase.paths())  # storage.from() names a bucket
        notes = " ".join(report["notes"])
        self.assertIn("since April 2026", notes)
        self.assertIn("Security Advisor", notes)
        for value in ROW_VALUES:
            self.assertNotIn(value, md)

    def test_W14_rls_on_is_clean(self):
        with Site(rls_on_routes()) as supabase:
            code, report, _ = self.run_anon(supabase)
        self.assertEqual(report["findings"], [], json.dumps(report["findings"], indent=1))
        self.assertEqual(code, 0)
        self.assertIn("returned no rows", " ".join(report["notes"]))

    def test_W14_does_nothing_without_anon_read(self):
        with Site(supabase_routes()) as supabase, Site(good_routes(), headers=GOOD_HEADERS) as site:
            _, report = run_json(site.url, "--supabase-url", supabase.url, "--only", "W14")
        self.assertEqual(report["findings"], [])
        self.assertEqual(supabase.requests, [])


# --- Politeness ------------------------------------------------------------------

class PolitenessTests(unittest.TestCase):
    def test_never_leaves_the_origin(self):
        with Site({"/x.js": (200, JS, "alert(1)"), "/x.css": (200, CSS, "a{}")}) as offsite:
            page = GOOD_HTML.replace(
                "</head>",
                f'<script src="{offsite.url}/x.js"></script><link rel="stylesheet" href="{offsite.url}/x.css">'
                '<script src="/assets/moved.js"></script></head>',
            ).replace("</main>", f'<a href="{offsite.url}/">partner</a><iframe src="{offsite.url}/"></iframe></main>')
            routes = {**good_routes(), "/": (200, HTML, page),
                      "/assets/moved.js": (302, {"Location": f"{offsite.url}/x.js"}, "")}
            with Site(routes, default=(404, HTML, GOOD_404), headers=GOOD_HEADERS) as site:
                code, report = run_json(site.url)
            self.assertEqual(offsite.requests, [])
        self.assertEqual(report["findings"], [])

    def test_request_cap_is_hard(self):
        with Site(good_routes(), default=(404, HTML, GOOD_404), headers=GOOD_HEADERS) as site:
            _, report = run_json(site.url, "--max-requests", "5")
        self.assertLessEqual(len(site.requests), 5)
        self.assertIn("Request cap of 5 reached", " ".join(report["notes"]))

    def test_stops_after_consecutive_failures(self):
        fetcher = probe.Fetcher(timeout=0.5, max_requests=150)
        url = f"http://127.0.0.1:{free_port()}/"
        fetcher.allow(url)
        results = [fetcher.get(f"{url}?n={i}") for i in range(12)]
        self.assertEqual(fetcher.count, probe.MAX_CONSECUTIVE_FAILURES)
        self.assertIn("not sent", results[-1].error)

    def test_redirect_to_another_site_aborts(self):
        with Site({}) as other:
            with Site({"/": (301, {"Location": f"{other.url}/"}, "")}) as site:
                code, out, err = run_probe(site.url)
            self.assertEqual(other.requests, [])
        self.assertEqual(code, 2)
        self.assertIn("another site", err)


# --- Network errors: a note and exit 2, never a traceback ----------------------

def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class NetworkErrorTests(unittest.TestCase):
    def test_connection_refused_exits_2_without_traceback(self):
        url = f"http://127.0.0.1:{free_port()}/"
        result = subprocess.run([sys.executable, str(HERE / "probe.py"), url, "--timeout", "2"],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("connection refused", result.stderr)
        self.assertIn("Probe aborted", result.stdout)

    def test_timeout_exits_2(self):
        with socket.socket() as silent:  # accepts the connection, never answers
            silent.bind(("127.0.0.1", 0))
            silent.listen(4)
            code, out, err = run_probe(f"http://127.0.0.1:{silent.getsockname()[1]}/", "--timeout", "0.3", "--format", "json")
        self.assertEqual(code, 2)
        self.assertIn("timed out", err)
        self.assertIn("timed out", " ".join(json.loads(out)["notes"]))

    def test_tls_error_exits_2(self):
        with Site({}) as site:  # plain http, so the TLS handshake fails
            code, _, err = run_probe(site.url.replace("http://", "https://"))
        self.assertEqual(code, 2)
        self.assertIn("TLS", err)

    def test_vercel_bot_challenge_aborts_instead_of_auditing_the_challenge_page(self):
        # Seen live: a Vercel Security Checkpoint answered every scripted GET, and the report
        # described the checkpoint page's headers as if they were the site's.
        page = (403, {"Content-Type": "text/html", "X-Vercel-Mitigated": "challenge"},
                "<html lang=en><title>Vercel Security Checkpoint</title></html>")
        with Site({"/": page}) as site:
            code, out, err = run_probe(site.url + "/", "--format", "json")
            self.assertEqual(site.paths(), ["/"])  # nothing probed past the challenge
        self.assertEqual(code, 2)
        self.assertEqual([], json.loads(out)["findings"])
        self.assertIn("bot challenge", err)

    def test_cloudflare_challenge_page_is_detected(self):
        resp = fake("https://shop.example/", 403, {"Content-Type": "text/html"},
                    b"<title>Just a moment...</title><script src='/cdn-cgi/challenge-platform/h/b/cf-chl-x'></script>")
        self.assertIn("challenge", probe.bot_challenge(resp))
        self.assertEqual("", probe.bot_challenge(fake("https://shop.example/", 403, {}, b"<h1>Forbidden</h1>")))

    def test_dns_failure_exits_2(self):
        with mock.patch("socket.getaddrinfo", side_effect=socket.gaierror(8, "nodename nor servname provided")):
            code, _, err = run_probe("https://shop.invalid/")
        self.assertEqual(code, 2)
        self.assertIn("DNS lookup failed", err)


# --- Decision functions for what local http can't show -------------------------

class DecisionTests(unittest.TestCase):
    def test_W04_http_not_redirected_to_https(self):
        findings, _ = probe.https_findings("https://shop.test/", [fake("http://shop.test/", 200, HTML)], None)
        self.assertEqual([(f.id, f.severity) for f in findings], [("W04", "P1")])

    def test_W04_http_target_without_working_https_is_P0(self):
        https = fake("https://shop.test/", error="TLS handshake failed (WRONG_VERSION_NUMBER)")
        findings, _ = probe.https_findings("http://shop.test/", [fake("http://shop.test/", 200, HTML)], https)
        self.assertEqual([(f.id, f.severity) for f in findings], [("W04", "P0")])
        self.assertIn("TLS handshake failed", findings[0].evidence)

    def test_W04_redirects_pass_including_a_www_hop(self):
        direct = [fake("http://shop.test/", 308, {"Location": "https://shop.test/"})]
        via_www = [fake("http://shop.test/", 301, {"Location": "http://www.shop.test/"}),
                   fake("http://www.shop.test/", 301, {"Location": "https://www.shop.test/"})]
        self.assertEqual(probe.https_findings("https://shop.test/", direct, None)[0], [])
        self.assertEqual(probe.https_findings("https://shop.test/", via_www, None)[0], [])
        https_ok = fake("https://shop.test/", 200, HTML)
        self.assertEqual(probe.https_findings("http://shop.test/", direct, https_ok)[0], [])

    def test_W04_closed_port_80_is_a_note_not_a_finding(self):
        findings, note = probe.https_findings("https://shop.test/", [fake("http://shop.test/", error="connection refused")], None)
        self.assertEqual(findings, [])
        self.assertIn("did not answer", note)

    def test_W05_hsts_missing_on_https(self):
        findings = probe.header_findings("https://shop.test/", {**GOOD_HEADERS})
        self.assertEqual([(f.severity, "Strict-Transport-Security" in f.evidence) for f in findings], [("P2", True)])
        clean = probe.header_findings("https://shop.test/", {**GOOD_HEADERS, "Strict-Transport-Security": "max-age=63072000"})
        self.assertEqual(clean, [])

    def test_W05_report_only_csp_is_P3_and_meta_csp_counts(self):
        headers = {k: v for k, v in GOOD_HEADERS.items() if k != "Content-Security-Policy"}
        report_only = probe.header_findings("http://shop.test/", {**headers, "Content-Security-Policy-Report-Only": "default-src 'self'"})
        self.assertEqual([(f.severity, "Report-Only" in f.evidence) for f in report_only], [("P3", True)])
        doc = probe.parse_html('<html><head><meta http-equiv="Content-Security-Policy" content="default-src \'self\'"></head></html>')
        self.assertEqual(probe.header_findings("http://shop.test/", headers, doc), [])

    def test_W06_cdn_node_tags_are_not_versions(self):
        for server in ("cloudflare", "Vercel", "ECS (nyb/1D2E)", "nginx", "AmazonS3"):
            self.assertEqual(probe.version_findings("https://shop.test/", {"Server": server}), [], server)
        for server in ("Apache/2.4.41 (Ubuntu)", "Microsoft-IIS/10.0", "gunicorn/20.1.0"):
            self.assertEqual(len(probe.version_findings("https://shop.test/", {"Server": server})), 1, server)

    def test_W09_server_rendered_root_is_clean(self):
        ssr = '<html><body><div id="__next"><main><h1>Menu</h1><p>Rye</p></main></div></body></html>'
        self.assertIsNone(probe.empty_mount(ssr, probe.parse_html(ssr)))
        shell = '<html><body><div id="app"></div><script src="/a.js"></script></body></html>'
        self.assertEqual(probe.empty_mount(shell, probe.parse_html(shell)), "app")

    def test_W03_validators_reject_html_pages_that_mention_the_signatures(self):
        page = b"<!doctype html><html><body><pre>API_KEY=x\n[core]\nCREATE TABLE t (id int);</pre></body></html>"
        for validator in (probe.validate_env, probe.validate_git_config, probe.validate_sql, probe.validate_git_head,
                          probe.validate_ds_store, probe.validate_zip):
            self.assertIsNone(validator(page), validator.__name__)

    def test_W10_ai_crawlers_blocked_is_P3_human(self):
        robots = "User-agent: GPTBot\nUser-agent: ClaudeBot\nDisallow: /\n\nUser-agent: *\nAllow: /\n"
        (finding,) = probe.robots_findings("https://shop.test/robots.txt", robots)
        self.assertEqual((finding.severity, finding.owner), ("P3", "HUMAN"))
        self.assertIn("claudebot, gptbot", finding.evidence)

    def test_W10_ordinary_robots_rules_are_clean(self):
        for robots in ("User-agent: *\nDisallow:\n", "User-agent: *\nDisallow: /admin\nDisallow: /api/\n", ""):
            self.assertEqual(probe.robots_findings("https://shop.test/robots.txt", robots), [], robots)

    def test_W11_framework_default_404_is_P3_design(self):
        resp = fake("https://shop.test/x", 404, HTML, b"<pre>Cannot GET /polish-website-404-check-7f3a9c</pre>")
        (finding,) = probe.not_found_findings("https://shop.test/x", resp)
        self.assertEqual((finding.severity, finding.area), ("P3", "design"))
        custom = fake("https://shop.test/x", 404, HTML, GOOD_404.encode())
        self.assertEqual(probe.not_found_findings("https://shop.test/x", custom), [])

    def test_W13_consent_tool_and_cookieless_analytics_do_not_fire(self):
        gtag = "<script src='https://www.googletagmanager.com/gtag/js'></script>"
        consent = "<script>gtag('consent','default',{analytics_storage:'denied'})</script>"
        self.assertEqual(probe.tracker_findings("https://s.test/", gtag + consent, {}, {}, "v"), [])
        plausible = "<script defer src='https://plausible.io/js/script.js'></script><script src='/_vercel/insights/script.js'></script>"
        self.assertEqual(probe.tracker_findings("https://s.test/", plausible, {}, {}, "v"), [])

    def test_W13_session_replay_in_bundle_only(self):
        js = {"https://s.test/assets/a.js": "LogRocket.init('acme/app');"}
        (finding,) = probe.tracker_findings("https://s.test/", "<html></html>", js, {}, "v")
        self.assertIn("LogRocket", finding.evidence)
        self.assertIn("not in the raw HTML", finding.evidence)
        self.assertIn("CIPA", finding.why)

    def test_W15_mixed_content_on_https_page(self):
        doc = probe.parse_html('<html><body><script src="http://cdn.test/a.js"></script>'
                               '<img src="http://img.test/b.png" alt=""><iframe src="https://ok.test/"></iframe></body></html>')
        (finding,) = probe.mixed_content_findings("https://shop.test/", doc)
        self.assertIn("2 http:// resource(s)", finding.evidence)

    def test_W15_https_resources_and_plain_links_are_clean(self):
        doc = probe.parse_html('<html><body><a href="http://partner.test/">partner</a>'
                               '<script src="https://cdn.test/a.js"></script><img src="/b.png" alt=""></body></html>')
        self.assertEqual(probe.mixed_content_findings("https://shop.test/", doc), [])


if __name__ == "__main__":
    unittest.main()
