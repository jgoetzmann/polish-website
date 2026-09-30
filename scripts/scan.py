#!/usr/bin/env python3
"""Static repo scan for polish-website.

Walks the repo once, computes a few project facts (stack, signup, native app, git),
then runs the S* (security), L* (legal), D* (design and copy) and M* (mobile app
store) rules. Each rule is one function that returns Finding objects.

    python3 scripts/scan.py [PATH] [--only IDS,AREAS] [--format md|json] [--fail-on P0] [--out FILE]
    python3 scripts/scan.py --list-rules

Stdlib only, Python 3.9+. No network calls.
"""

from __future__ import annotations

import argparse
import bisect
import fnmatch
import json
import os
import re
import shlex
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Callable, Iterable, Iterator
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import (  # noqa: E402
    AREAS, JWT, PLACEHOLDER, SECRET_PATTERNS, Finding, add_output_args, emit, exit_code,
    find_secrets, jwt_payload, redact, render, rules_table,
)

# Play floor since 2026-08-31 (API 36); rises every August — confirm in Play Console.
PLAY_TARGET_SDK_FLOOR = 36

TOOL = "scan.py"

# --- Walk --------------------------------------------------------------------

SKIP_DIRS = frozenset(
    "node_modules .git dist build out .next .nuxt .svelte-kit .output .vercel .netlify .turbo "
    ".expo coverage vendor Pods .venv venv __pycache__ .polish-website DerivedData .gradle".split()
)
SKIP_PATHS = ("android/app/build", "ios/build")
LOCKFILES = frozenset("package-lock.json yarn.lock pnpm-lock.yaml bun.lockb poetry.lock".split())
MAX_BYTES = 1_000_000
BINARY_EXTS = frozenset(
    ".png .jpg .jpeg .gif .webp .avif .ico .icns .bmp .tiff .psd .woff .woff2 .ttf .otf .eot .mp3 .mp4 "
    ".mov .webm .wav .ogg .pdf .zip .gz .tgz .tar .7z .rar .jar .aar .apk .aab .ipa .keystore .jks .p12 "
    ".mobileprovision .so .dylib .dll .exe .a .o .class .dex .pyc .wasm .sqlite .db .lockb .car".split()
)

USER_FACING_EXTS = frozenset(".tsx .jsx .html .vue .svelte .astro .mdx".split())
MD_DIRS = frozenset("content app pages src posts blog".split())
CODE_EXTS = frozenset(
    ".js .jsx .ts .tsx .mjs .cjs .mts .cts .vue .svelte .astro .html .htm .py .rb .php .go .rs "
    ".java .kt .kts .swift .dart .erb .hbs .ejs".split()
)
JS_EXTS = frozenset(".js .jsx .ts .tsx .mjs .cjs .mts .cts .vue .svelte .astro".split())
STYLE_EXTS = frozenset(".css .scss .sass .less .styl .pcss".split())
COMPONENT_EXTS = (".tsx", ".jsx", ".vue", ".svelte")
DOC_EXTS = frozenset(".md .txt .rst .adoc".split())
# Files whose contents reach a visitor's browser: tracker and font checks look only here, so a
# Python crawler that lists tracker hosts is not "loading" them.
WEB_EXTS = JS_EXTS | STYLE_EXTS | frozenset(".html .htm .php .erb .hbs .ejs .twig .njk .liquid .jinja .j2".split())

TEST_DIRS = frozenset("__tests__ __mocks__ __fixtures__ test tests e2e cypress playwright spec stories fixtures".split())
TEST_NAME = re.compile(r"\.(?:test|spec|stories|story|cy|e2e)\.[A-Za-z]+$|^test_.*\.py$|_test\.(?:py|go)$|^conftest\.py$")
DOC_NAME = re.compile(r"^(?:README|CHANGELOG|LICENSE|LICENCE|CONTRIBUTING|CODE_OF_CONDUCT|SECURITY)", re.I)
DOC_DIRS = frozenset("docs .claude .github".split())

ENV_NAME = re.compile(r"(?:[\w.\-]+)?\.env(?:\..+)?")  # .env, .env.local, keepalive.env
ENV_EXAMPLE = re.compile(r"\.(?:example|sample|template|defaults|dist)\b")

# Paths that mark a component file as server-only (S06, S14).
SERVER_PATH_HINTS = ("/api/", "/server/", "supabase/functions/", "route.", ".server.", "actions", "middleware")


# --- Text helpers ------------------------------------------------------------

def blank(text: str) -> str:
    """Same length, newlines kept: comments vanish without moving line numbers."""
    return re.sub(r"[^\n]", " ", text)


_JS_TOKENS = re.compile(
    r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'|`(?:[^`\\]|\\.)*`'  # strings, kept as-is
    r"|/\*.*?\*/"                                                    # block comment
    r"|(?<![:\w\"'`\\/])//[^\n]*"                                    # line comment, not https://
    r"|<!--.*?-->",
    re.S,
)
_CSS_TOKENS = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'|/\*.*?\*/', re.S)
_MARKUP_COMMENT = re.compile(r"<!--.*?-->", re.S)
_HASH_COMMENT = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'|#[^\n]*')


def _keep_strings(m: re.Match) -> str:
    s = m.group(0)
    return s if s[0] in "\"'`" else blank(s)


def strip_comments(text: str, ext: str) -> str:
    if ext in (".md", ".xml", ".svg"):
        return _MARKUP_COMMENT.sub(lambda m: blank(m.group(0)), text)
    if ext in (".css", ".pcss"):
        return _CSS_TOKENS.sub(_keep_strings, text)
    if ext in (".py", ".rb", ".toml", ".yaml", ".yml"):
        return _HASH_COMMENT.sub(_keep_strings, text)
    if ext in JS_EXTS or ext in STYLE_EXTS or ext in (".html", ".htm", ".mdx", ".rules", ".php", ".go",
                                                      ".java", ".kt", ".swift", ".dart", ".json"):
        return _JS_TOKENS.sub(_keep_strings, text)
    return text


def scrub(text: str) -> str:
    """Replace anything that looks like a secret with its redacted form."""
    for _kind, pattern in SECRET_PATTERNS:
        text = pattern.sub(lambda m: m.group(0) if PLACEHOLDER.search(m.group(0)) else redact(m.group(0)), text)
    return JWT.sub(lambda m: redact(m.group(0)), text)


_ENV_ASSIGN = re.compile(r"^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.\-]*\s*[=:]\s*)(\S.*?)\s*$")


def clip(text: str) -> str:
    """Evidence text: secrets redacted, whitespace collapsed, at most 160 characters."""
    text = " ".join(scrub(str(text)).split())
    return text if len(text) <= 160 else text[:159] + "…"


def top_files(counter: Counter, n: int = 5) -> str:
    return ", ".join(f"{path} ({count})" for path, count in counter.most_common(n))


def path_words(rel: str) -> list[str]:
    return [w for w in re.split(r"[/._\-()\[\]+@]+", rel.lower()) if w]


def matching_brace(text: str, open_at: int, limit: int = 20000) -> int:
    """Index just past the brace/paren that closes text[open_at], ignoring quoted text."""
    pairs = {"{": "}", "(": ")", "[": "]"}
    opener = text[open_at]
    closer = pairs[opener]
    depth, i, end = 0, open_at, min(len(text), open_at + limit)
    quote = ""
    while i < end:
        c = text[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote:
                quote = ""
        elif c in "\"'`":
            quote = c
        elif c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return end


def read_tag(text: str, start: int, limit: int = 3000) -> str:
    """The text of a JSX/HTML tag from '<' to its closing '>', skipping '>' inside {...} and quotes."""
    depth, i, end = 0, start + 1, min(len(text), start + limit)
    quote = ""
    while i < end:
        c = text[i]
        if quote:
            if c == quote:
                quote = ""
        elif c in "\"'" and depth == 0:
            quote = c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth = max(0, depth - 1)
        elif c == ">" and depth == 0:
            return text[start:i + 1]
        i += 1
    return text[start:end]


# --- Source files ------------------------------------------------------------

@dataclass
class SourceFile:
    rel: str   # posix path relative to the scan root
    text: str

    @cached_property
    def name(self) -> str:
        return self.rel.rsplit("/", 1)[-1]

    @cached_property
    def ext(self) -> str:
        dot = self.name.rfind(".")
        return self.name[dot:].lower() if dot > 0 else ""

    @cached_property
    def dirs(self) -> list[str]:
        return self.rel.split("/")[:-1]

    @cached_property
    def lines(self) -> list[str]:
        return self.text.split("\n")

    @cached_property
    def _newlines(self) -> list[int]:
        return [i for i, c in enumerate(self.text) if c == "\n"]

    def line_at(self, offset: int) -> int:
        return bisect.bisect_right(self._newlines, offset - 1) + 1

    def line(self, n: int) -> str:
        return self.lines[n - 1] if 0 < n <= len(self.lines) else ""

    def where(self, n: int) -> str:
        return f"{self.rel}:{n}"

    def window(self, n: int, before: int, after: int) -> str:
        return "\n".join(self.lines[max(0, n - 1 - before):n + after])

    def evidence(self, n: int) -> str:
        """The line as evidence; in .env files the value is always redacted, whatever its shape."""
        text = self.line(n)
        if self.is_env:
            m = _ENV_ASSIGN.match(text)
            if m:
                text = m.group(1) + redact(m.group(2))
        return clip(text)

    @cached_property
    def code(self) -> str:
        """Text with comments blanked out; line numbers unchanged."""
        return strip_comments(self.text, self.ext)

    @cached_property
    def is_lock(self) -> bool:
        return self.name in LOCKFILES

    @cached_property
    def is_env(self) -> bool:
        return bool(ENV_NAME.fullmatch(self.name))

    @cached_property
    def is_env_example(self) -> bool:
        return self.is_env and bool(ENV_EXAMPLE.search(self.name))

    @cached_property
    def is_test(self) -> bool:
        return bool(TEST_NAME.search(self.name)) or any(d in TEST_DIRS for d in self.dirs)

    @cached_property
    def is_doc(self) -> bool:
        return bool(DOC_NAME.match(self.name)) or any(d in DOC_DIRS for d in self.dirs)

    @cached_property
    def is_minified(self) -> bool:
        """Minified bundles, and HTML that a framework built (a saved page, stray build output)."""
        if ".min." in self.name:
            return True
        return self.ext in (".html", ".htm") and bool(BUILT_HTML.search(self.text[:20000]))

    @cached_property
    def is_code(self) -> bool:
        return self.ext in CODE_EXTS and not (self.is_test or self.is_minified or self.is_doc)

    @cached_property
    def user_facing(self) -> bool:
        if self.is_test or self.is_doc or self.is_minified or ".config." in self.name:
            return False
        if self.ext in USER_FACING_EXTS:
            return True
        return self.ext == ".md" and any(d in MD_DIRS for d in self.dirs)

    @cached_property
    def is_style(self) -> bool:
        return self.ext in STYLE_EXTS and not (self.is_test or self.is_minified)

    @cached_property
    def client_kind(self) -> str | None:
        """'directive' for a 'use client' file, 'likely' for a component outside server paths."""
        head = self.code.lstrip()[:20]
        if re.match(r"""["']use client["']""", head):
            return "directive"
        if re.match(r"""["']use server["']""", head):
            return None
        if self.ext in COMPONENT_EXTS and not any(h in "/" + self.rel for h in SERVER_PATH_HINTS):
            return "likely"
        return None

    @cached_property
    def copy(self) -> str:
        """Comment-free text with import lines and placeholder= values blanked (copy rules).

        In HTML-like files, <script> and <style> bodies are code, not copy, so they're blanked too.
        """
        text = self.code
        if self.ext in (".html", ".htm", ".vue", ".svelte", ".astro"):
            text = SCRIPT_STYLE_BODY.sub(lambda m: m.group(1) + blank(m.group(3)) + m.group(4), text)
        text = re.sub(r"(?m)^\s*import\b[^\n]*$", lambda m: blank(m.group(0)), text)
        text = PLACEHOLDER_ATTR.sub(lambda m: blank(m.group(0)), text)
        return text


BUILT_HTML = re.compile(r"/_next/static/|data-next-head|__NEXT_DATA__|/_nuxt/|/wp-content/|/wp-includes/|__remixContext")
SCRIPT_STYLE_BODY = re.compile(r"(<(script|style)\b[^>]*>)(.*?)(</\2\s*>)", re.I | re.S)
PLACEHOLDER_ATTR = re.compile(r"""placeholder\s*[=:]\s*\{?\s*(?:"[^"\n]*"|'[^'\n]*'|`[^`\n]*`)""", re.I)


def is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def walk(root: Path) -> tuple[list[str], list[SourceFile]]:
    """All file paths (relative, posix) and the text files among them."""
    paths: list[str] = []
    files: list[SourceFile] = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS and f"{rel_dir}/{d}".lstrip("/") not in SKIP_PATHS
        )
        for name in sorted(filenames):
            rel = f"{rel_dir}/{name}".lstrip("/")
            full = Path(dirpath) / name
            paths.append(rel)
            ext = name[name.rfind("."):].lower() if "." in name[1:] else ""
            if ext in BINARY_EXTS or name in ("bun.lockb", ".DS_Store"):
                continue
            try:
                if full.is_symlink() and not full.exists():
                    continue
                if full.stat().st_size > MAX_BYTES:
                    continue
                data = full.read_bytes()
            except OSError:
                continue
            if is_binary(data):
                continue
            files.append(SourceFile(rel, data.decode("utf-8", errors="replace")))
    return paths, files


# --- Dependencies ------------------------------------------------------------

def py_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _add_dep(deps: dict[str, str], name: str, where: str) -> None:
    deps.setdefault(name, where)


def read_deps(files: list[SourceFile]) -> dict[str, str]:
    """Dependency name -> 'path:line' of its first declaration."""
    deps: dict[str, str] = {}
    for f in files:
        if f.is_test:
            continue
        if f.name == "package.json":
            _package_json_deps(f, deps)
        elif f.name.startswith("requirements") and f.name.endswith(".txt"):
            for i, line in enumerate(f.lines, 1):
                m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._\-]*)", line)
                if m and not line.lstrip().startswith(("#", "-")):
                    _add_dep(deps, py_name(m.group(1)), f.where(i))
        elif f.name == "pyproject.toml":
            _pyproject_deps(f, deps)
        elif f.name == "pubspec.yaml":
            _pubspec_deps(f, deps)
    return deps


def _package_json_deps(f: SourceFile, deps: dict[str, str]) -> None:
    try:
        data = json.loads(f.text)
    except ValueError:
        return
    if not isinstance(data, dict):
        return
    for section in ("dependencies", "devDependencies"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name in block:
            idx = f.text.find(f'"{name}"')
            _add_dep(deps, name.lower(), f.where(f.line_at(idx) if idx >= 0 else 1))


def _pyproject_deps(f: SourceFile, deps: dict[str, str]) -> None:
    section, in_array = "", False
    for i, raw in enumerate(f.lines, 1):
        line = raw.split("#", 1)[0].strip()
        if in_array:
            for m in re.finditer(r"""["']([A-Za-z0-9][A-Za-z0-9._\-]*)""", line):
                _add_dep(deps, py_name(m.group(1)), f.where(i))
            in_array = "]" not in line
            continue
        if line.startswith("["):
            section = line.strip("[] ")
            continue
        m = re.match(r"([\w\-]+)\s*=\s*\[(.*)$", line)
        array_ok = section in ("project.optional-dependencies", "dependency-groups") or (
            section == "project" and m is not None and m.group(1) == "dependencies")
        if m and array_ok:
            for d in re.finditer(r"""["']([A-Za-z0-9][A-Za-z0-9._\-]*)""", m.group(2)):
                _add_dep(deps, py_name(d.group(1)), f.where(i))
            in_array = "]" not in m.group(2)
            continue
        if section.startswith("tool.poetry") and section.endswith("dependencies"):
            m = re.match(r"([A-Za-z0-9][A-Za-z0-9._\-]*)\s*=", line)
            if m and m.group(1).lower() != "python":
                _add_dep(deps, py_name(m.group(1)), f.where(i))


def _pubspec_deps(f: SourceFile, deps: dict[str, str]) -> None:
    in_deps = False
    for i, line in enumerate(f.lines, 1):
        if re.match(r"^(?:dependencies|dev_dependencies):\s*$", line):
            in_deps = True
            continue
        if re.match(r"^\S", line):
            in_deps = False
            continue
        m = re.match(r"^  ([A-Za-z0-9_]+)\s*:", line)
        if in_deps and m:
            _add_dep(deps, m.group(1), f.where(i))


# --- Git ---------------------------------------------------------------------

def git(root: Path, *args: str, stdin: str | None = None, timeout: int = 60) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(
            ["git", "-C", str(root), *args], input=stdin, capture_output=True, text=True,
            errors="replace", timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return None


# --- Repo --------------------------------------------------------------------

SIGNUP_CALL = re.compile(r"\bsignUp\s*\(|createUserWithEmailAndPassword|auth\.admin\.createUser|<SignUp\b")
SIGNUP_LINK = re.compile(r"[\"'`]/(?:sign-?up|register)\b")
SIGNUP_PATH_WORDS = frozenset(("signup", "sign-up", "sign_up", "register"))
WEB_FRAMEWORK_DEPS = ("next", "vite", "nuxt", "@sveltejs/kit", "astro", "gatsby", "react-scripts", "@remix-run/*")


class Repo:
    def __init__(self, root: Path, target: str):
        self.root = root
        self.target = target
        self.notes: list[str] = []
        self.paths, self.files = walk(root)
        self.path_set = set(self.paths)
        self.by_path = {f.rel: f for f in self.files}
        self.deps = read_deps(self.files)
        self.is_git = self._is_git()
        self.native = self._native_kinds()
        self.has_native = bool(self.native)
        self.has_ios = bool(self.native & {"ios", "expo"}) or self.has_dep("@capacitor/ios")
        self.has_android = bool(self.native & {"android", "expo"}) or self.has_dep("@capacitor/android")
        self.has_web = self._has_web()
        self.signup_where = self._signup_where()
        self.has_signup = self.signup_where is not None

    # facts

    def _is_git(self) -> bool:
        r = git(self.root, "rev-parse", "--is-inside-work-tree")
        return bool(r and r.returncode == 0 and r.stdout.strip() == "true")

    def _native_kinds(self) -> set[str]:
        kinds: set[str] = set()
        for p in self.paths:
            name = p.rsplit("/", 1)[-1]
            if re.fullmatch(r"capacitor\.config\.(?:ts|js|mjs|cjs|json)", name):
                kinds.add("capacitor")
            if name == "pubspec.yaml":
                kinds.add("flutter")
            if re.search(r"(?:^|/)android/app/build\.gradle(?:\.kts)?$", p):
                kinds.add("android")
            if re.search(r"(?:^|/)ios/(?:.*/)?[^/]+\.xcodeproj/", p):
                kinds.add("ios")
        for f in self.files:
            if f.name == "app.json" and '"expo"' in f.text:
                kinds.add("expo")
            elif re.fullmatch(r"app\.config\.(?:js|ts|mjs|cjs)", f.name) and re.search(r"\bexpo\b", f.text):
                kinds.add("expo")
            elif f.name == "config.xml" and "<widget" in f.text and "cordova" in f.text.lower():
                kinds.add("cordova")
        if self.has_dep("expo"):
            kinds.add("expo")
        if self.has_dep("react-native"):
            kinds.add("rn")
        if self.has_dep("cordova-android", "cordova-ios"):
            kinds.add("cordova")
        return kinds

    def _has_web(self) -> bool:
        user = [f for f in self.files if f.user_facing]
        if not user:
            return False
        # React Native and Expo screens are .tsx too; they only count as a website when
        # the repo also has HTML or a web framework.
        if self.native & {"expo", "rn"}:
            return any(f.ext in (".html", ".htm") for f in user) or self.has_dep(*WEB_FRAMEWORK_DEPS)
        return True

    def _signup_where(self) -> str | None:
        hit = self.first(SIGNUP_CALL, self.code_files())
        if hit:
            return hit[0].where(hit[1])
        for p in self.paths:
            words = [w.lower() for w in re.split(r"[/()]+", p) if w]
            stems = [w.rsplit(".", 1)[0] if i == len(words) - 1 else w for i, w in enumerate(words)]
            if any(s in SIGNUP_PATH_WORDS for s in stems) and not TEST_NAME.search(p):
                return f"{p}:1"
        hit = self.first(SIGNUP_LINK, self.code_files())
        return hit[0].where(hit[1]) if hit else None

    # file sets

    def pattern_files(self) -> list[SourceFile]:
        return [f for f in self.files if not f.is_lock]

    def code_files(self) -> list[SourceFile]:
        return [f for f in self.files if f.is_code]

    def user_files(self) -> list[SourceFile]:
        return [f for f in self.files if f.user_facing]

    def design_files(self) -> list[SourceFile]:
        return [f for f in self.files if f.user_facing or f.is_style]

    def source_files(self) -> list[SourceFile]:
        """Code, markup, styles and config: everything except lockfiles, tests and docs."""
        return [f for f in self.files if not (f.is_lock or f.is_test or f.is_doc or f.is_minified)
                and f.ext not in DOC_EXTS]

    def web_files(self) -> list[SourceFile]:
        return [f for f in self.source_files() if f.ext in WEB_EXTS or f.name == "package.json"]

    def sql_files(self) -> list[SourceFile]:
        return [f for f in self.files if f.ext == ".sql" and not f.is_test]

    # searching

    def first(self, pattern: re.Pattern, files: Iterable[SourceFile], use_code: bool = True) -> tuple[SourceFile, int] | None:
        for f in files:
            m = pattern.search(f.code if use_code else f.text)
            if m:
                return f, f.line_at(m.start())
        return None

    def count(self, pattern: re.Pattern, files: Iterable[SourceFile], attr: str = "code") -> Counter:
        counts: Counter = Counter()
        for f in files:
            n = len(pattern.findall(getattr(f, attr)))
            if n:
                counts[f.rel] += n
        return counts

    def has_dep(self, *names: str) -> bool:
        return bool(self.deps_matching(names))

    def deps_matching(self, names: Iterable[str]) -> list[str]:
        found = []
        for name in names:
            if name.endswith("/*"):
                found += sorted(d for d in self.deps if d.startswith(name[:-1]))
            elif name in self.deps:
                found.append(name)
        return found

    def verify(self, rule_id: str) -> str:
        return f"python3 scripts/scan.py --only {rule_id} {shlex.quote(self.target)}"

    # git-backed facts, computed on demand

    @cached_property
    def git_tracked(self) -> list[str]:
        r = git(self.root, "ls-files", "-z")
        return [p for p in r.stdout.split("\0") if p] if r and r.returncode == 0 else []

    def git_ignored(self, paths: list[str], no_index: bool = False) -> set[str]:
        if not paths:
            return set()
        args = ["check-ignore", "--stdin"] + (["--no-index"] if no_index else [])
        r = git(self.root, *args, stdin="\n".join(paths) + "\n")
        return {p.strip() for p in r.stdout.splitlines() if p.strip()} if r else set()

    @cached_property
    def secret_skip(self) -> set[str]:
        """.env files S02 leaves alone: git-ignored ones, or all of them outside git."""
        envs = [f.rel for f in self.files if f.is_env and not f.is_env_example]
        return self.git_ignored(envs) if self.is_git else set(envs)

    @cached_property
    def worktree_secrets(self) -> list[tuple[SourceFile, str, str, int]]:
        hits = []
        for f in self.pattern_files():
            if f.rel in self.secret_skip:
                continue
            for kind, red, offset in find_secrets(f.text):
                n = f.line_at(offset)
                if real_secret(f.text, offset, kind, f.line(n)):
                    hits.append((f, kind, red, n))
        return hits

    @cached_property
    def sql_statements(self) -> list[tuple[SourceFile, int, str]]:
        out = []
        for f in self.sql_files():
            for offset, stmt in sql_statements(f.text):
                out.append((f, f.line_at(offset), stmt))
        return out

    @cached_property
    def web_root(self) -> str:
        """The package that holds the site: 'apps/web/' in a monorepo, '' for a single app."""
        user = [f.rel for f in self.user_files()]
        if not user:
            return ""
        roots = {""} | {p[:-len("package.json")] for p in self.paths if p.endswith("/package.json")}
        counts = {r: sum(1 for u in user if u.startswith(r)) for r in roots}
        best = max(counts.values())
        return max((r for r, c in counts.items() if c >= 0.8 * best), key=lambda r: (r.count("/"), r))

    def route_hint(self, slug: str) -> str:
        """Where a new page would go in this stack, for 'missing page' findings."""
        root = self.web_root
        for base, pattern in (("src/app", "src/app/{}/page.tsx"), ("app", "app/{}/page.tsx"),
                              ("src/pages", "src/pages/{}.tsx"), ("pages", "pages/{}.tsx"),
                              ("src/routes", "src/routes/{}/+page.svelte")):
            if any(p.startswith(root + base + "/") for p in self.paths):
                if base == "src/routes" and not self.has_dep("@sveltejs/kit"):
                    pattern = "src/routes/{}.tsx"
                return root + pattern.format(slug)
        return f"{root}public/{slug}.html"


# --- SQL helpers -------------------------------------------------------------

_SQL_CLEAN = re.compile(r"'(?:[^']|'')*'|\$(\w*)\$.*?\$\1\$|--[^\n]*|/\*.*?\*/", re.S)
_SQL_SPLIT = re.compile(r"'(?:[^']|'')*'|\$(\w*)\$.*?\$\1\$|;", re.S)
_SQL_BODY = re.compile(r"\$(\w*)\$.*?\$\1\$", re.S)
SQL_IDENT = r'(?:"[^"]+"|[A-Za-z_][\w$]*)'
SQL_QNAME = rf"({SQL_IDENT}(?:\s*\.\s*{SQL_IDENT})?)"


def sql_statements(text: str) -> list[tuple[int, str]]:
    """Split SQL into (offset, statement) with comments blanked; quoted and $$ bodies stay whole."""
    clean = _SQL_CLEAN.sub(lambda m: blank(m.group(0)) if m.group(0)[:2] in ("--", "/*") else m.group(0), text)
    out, start = [], 0
    for m in _SQL_SPLIT.finditer(clean):
        if m.group(0) == ";":
            out.append((start, clean[start:m.end()]))
            start = m.end()
    if clean[start:].strip():
        out.append((start, clean[start:]))
    result = []
    for offset, stmt in out:
        lead = len(stmt) - len(stmt.lstrip())
        if stmt.strip():
            result.append((offset + lead, stmt.strip()))
    return result


def sql_name(raw: str) -> tuple[str, str]:
    """('schema', 'table') with quotes removed and case folded; no schema means public."""
    parts = [p.strip().strip('"').lower() for p in re.split(r"\s*\.\s*(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)", raw.strip())]
    return (parts[0], parts[1]) if len(parts) == 2 else ("public", parts[0])


def split_top_level(s: str, sep: str = ",") -> list[str]:
    """Split on sep outside quotes and brackets."""
    parts, depth, quote, cur = [], 0, "", []
    for c in s:
        if quote:
            if c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == sep and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
            continue
        cur.append(c)
    parts.append("".join(cur).strip())
    return parts


def first_line(stmt: str) -> str:
    return stmt.strip().split("\n", 1)[0]


# --- Rules -------------------------------------------------------------------

@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    area: str
    owner: str
    title: str
    check: Callable[[Repo, "Rule"], list]
    needs: tuple = ()  # facts that must hold for the rule to run: "git", "signup", "native"

    def hit(self, repo: Repo, where: str, evidence: str, why: str, fix: str,
            severity: str | None = None, verify: str | None = None, area: str | None = None) -> Finding:
        return Finding(self.id, severity or self.severity, area or self.area, self.owner,
                       where, clip(evidence), why, fix, verify or repo.verify(self.id))


def per_file(rule: Rule, repo: Repo, files: Iterable[SourceFile], pattern: re.Pattern, why: str, fix: str,
             attr: str = "code", severity_for: Callable[[SourceFile], str] | None = None,
             keep: Callable[[SourceFile, re.Match], bool] | None = None) -> list[Finding]:
    """One finding per file: the first matching line and how many matches the file has."""
    out = []
    for f in files:
        text = getattr(f, attr)
        matches = [m for m in pattern.finditer(text) if keep is None or keep(f, m)]
        if not matches:
            continue
        n = f.line_at(matches[0].start())
        more = f" ({len(matches)} in this file)" if len(matches) > 1 else ""
        out.append(rule.hit(repo, f.where(n), f.evidence(n) + more, why, fix,
                            severity=severity_for(f) if severity_for else None))
    return out


# --- S: secrets, data, auth, abuse, ops ---------------------------------------

PUBLIC_ENV_NAME = re.compile(r"\b(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|NUXT_PUBLIC_|GATSBY_|PUBLIC_)[A-Z0-9_]+")
SECRET_WORDS = re.compile(
    r"SECRET|SERVICE_ROLE|SERVICE_KEY|PRIVATE|PASSWORD|SK_LIVE|STRIPE_SECRET|OPENAI|ANTHROPIC|DATABASE_URL|"
    r"DB_URL|WEBHOOK_SECRET|RESEND|SENDGRID|TWILIO_AUTH"
)


def s01_public_env_secret(repo: Repo, rule: Rule) -> list[Finding]:
    seen: dict[str, tuple[SourceFile, int, str]] = {}
    for f in repo.pattern_files():
        for m in PUBLIC_ENV_NAME.finditer(f.text):
            name = m.group(0)
            if name not in seen and SECRET_WORDS.search(name[len(m.group(1)):]):
                seen[name] = (f, f.line_at(m.start()), m.group(1))
    return [
        rule.hit(
            repo, f.where(n), f.evidence(n),
            f"Bundlers inline every {prefix} variable into the JavaScript sent to every visitor, "
            f"so anyone can read {name} in the browser's dev tools.",
            f"Rename it without the {prefix} prefix, read it only in server code (route handler, server "
            "action, edge function), and rotate the key if a build with it ever shipped.",
        )
        for name, (f, n, prefix) in seen.items()
    ]


FAKE_CONTEXT = re.compile(r"\b(?:fake|dummy|mock|fixture)\w*|not[_\s\-]?a[_\s\-]?real|redacted", re.I)
LOCAL_DB_HOSTS = frozenset("host db database postgres postgresql pg mysql mariadb mongo mongodb redis supabase_db".split())
SYNTHETIC = re.compile(r"(.)\1{5,}|abcdef|123456|a1b2c3|1a2b3c|test[_\-]?key|fake|dummy", re.I)


def _raw_match(text: str, offset: int, kind: str) -> str:
    for k, pattern in SECRET_PATTERNS:
        m = pattern.match(text, offset) if k == kind else None
        if m:
            return m.group(0)
    m = JWT.match(text, offset)
    return m.group(0) if m else ""


def real_secret(text: str, offset: int, kind: str, line: str) -> bool:
    """Drop the test fixtures that find_secrets can't tell apart from real keys.

    Fake-named values, runs like 'BBBBBB' or 'abcdef', a PEM header with no key body (code that
    checks for PEM), Supabase's public local-dev JWT, and docker-style database URLs
    (postgres://app:app@db). A long password on an internal hostname is still reported.
    """
    if FAKE_CONTEXT.search(line):
        return False
    value = _raw_match(text, offset, kind)
    if kind == "private key":
        # A real key has a base64 body before its END line; code that tests for the header does not.
        end = text.find("-----END", offset + len(value), offset + 20000)
        if end < 0:
            return False
        between = re.sub(r"\\n|[\s\"'`+,()]", "", text[offset + len(value):end])
        body = "".join(re.findall(r"[A-Za-z0-9+/=]+", between))
        return len(body) >= 40 and len(body) >= 0.9 * len(between) and len(set(body)) >= 30
    if kind == "Supabase service_role JWT":
        return (jwt_payload(value) or {}).get("iss") != "supabase-demo"
    if kind == "database URL with password":
        try:
            parsed = urlparse(value.rstrip(").,;:]}>"))
            host, password = parsed.hostname or "", parsed.password or ""
        except ValueError:
            host, password = "", ""
        if host and "." not in host and (host in LOCAL_DB_HOSTS or len(password) < 8):
            return False
    return not SYNTHETIC.search(value)


def s02_hardcoded_secret(repo: Repo, rule: Rule) -> list[Finding]:
    groups: dict[tuple[str, str], list] = {}
    for f, kind, red, n in repo.worktree_secrets:
        entry = groups.setdefault((f.rel, kind), [f, n, red, 0])
        entry[3] += 1
    out = []
    for (_rel, kind), (f, n, red, count) in groups.items():
        more = f"; {count} in this file" if count > 1 else ""
        out.append(rule.hit(
            repo, f.where(n), f"{kind} {red}{more}",
            "Anyone who can read this file (a teammate, a leaked build, a public repo, a bot scanning GitHub) "
            "can use the key to spend money or read data in your account.",
            "Move the value to an environment variable (host dashboard or a git-ignored .env file), then rotate "
            "the key in the provider dashboard: removing it from code does not un-leak it.",
        ))
    return out


def s03_env_tracked(repo: Repo, rule: Rule) -> list[Finding]:
    out = []
    for rel in repo.git_tracked:
        name = rel.rsplit("/", 1)[-1]
        if ENV_NAME.fullmatch(name) and not ENV_EXAMPLE.search(name):
            out.append(rule.hit(
                repo, f"{rel}:1", f"git ls-files lists {rel}",
                "Everyone with access to the repo (everyone, if it is ever made public) gets every key in this "
                "file, and it stays in git history after you delete it.",
                f"Run `git rm --cached {rel}`, add `.env*` and `!.env.example` to .gitignore, then rotate every "
                "key the file contains.",
                verify="git ls-files | grep -E '(^|/)\\.env'",
            ))
    return out


HISTORY_PREFILTER = re.compile(r"_live_|sk-|sb_secret_|AKIA|ASIA|gh[pousr]_|github_pat_|xox[baprs]-|SG\.|PRIVATE KEY|://|eyJ")
HISTORY_MAX_COMMITS = 3000
HISTORY_MAX_BYTES = 50 * 1024 * 1024


def git_added_lines(repo: Repo) -> Iterator[tuple[str, str, str]]:
    """(short commit, path, added line) for every '+' line in history, within the caps."""
    cmd = ["git", "-C", str(repo.root), "log", "--all", "-p", "--no-color", "--no-ext-diff", "-U0",
           f"--max-count={HISTORY_MAX_COMMITS}", "--pretty=format:%x1fCOMMIT %h"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        return
    total, commit, path = 0, "", ""
    assert proc.stdout is not None
    try:
        for raw in proc.stdout:
            total += len(raw)
            if total > HISTORY_MAX_BYTES:
                repo.notes.append("S04 stopped after 50 MB of git history; run gitleaks for the rest.")
                break
            line = raw.decode("utf-8", errors="replace").rstrip("\n")
            if line.startswith("\x1fCOMMIT "):
                commit = line.split(" ", 1)[1].strip()
            elif line.startswith("+++ "):
                path = line[6:] if line.startswith("+++ b/") else line[4:]
            elif line.startswith("+"):
                yield commit, path, line[1:]
    finally:
        proc.kill()
        proc.stdout.close()
        proc.wait()


def s04_history_secret(repo: Repo, rule: Rule) -> list[Finding]:
    repo.notes.append("S04 reads added lines in up to 3000 commits; gitleaks or trufflehog scan history more thoroughly.")
    current = {red for _f, _kind, red, _n in repo.worktree_secrets}
    found: dict[tuple[str, str], list] = {}
    for commit, path, line in git_added_lines(repo):
        if path.rsplit("/", 1)[-1] in LOCKFILES or not HISTORY_PREFILTER.search(line):
            continue
        for kind, red, offset in find_secrets(line):
            if red in current or not real_secret(line, offset, kind, line):
                continue
            entry = found.setdefault((kind, red), [commit, path, 0])
            entry[2] += 1
    out = []
    for (kind, red), (commit, path, count) in found.items():
        more = f" ({count} additions in history)" if count > 1 else ""
        out.append(rule.hit(
            repo, f"{path}:1", f"{kind} {red} added in commit {commit} to {path}{more}",
            "Anyone who clones the repo can run `git log -p` and recover the key, so it works for an attacker "
            "until it is rotated, even though the current code no longer has it.",
            "Rotate the key in the provider dashboard now; rewriting history (git filter-repo) is optional after "
            "rotation and does nothing for copies already cloned. Consider gitleaks in CI.",
        ))
    return out


ENV_READ = re.compile(
    r"""(?:process\.env|import\.meta\.env)(?:\.(\w+)|\[\s*["'](\w+)["']\s*\])?|os\.environ(?:\.get\(\s*|\[\s*)?["']?(\w+)?"""
    r"""|os\.getenv\(\s*["'](\w+)|Deno\.env\.get\(\s*["'](\w+)"""
)
BUILTIN_ENV = re.compile(r"NODE_ENV|DEV|PROD|MODE|BASE_URL|SSR|CI|HOME|PATH|PWD|USER|SHELL|TERM|TZ|LANG|PORT|"
                         r"(?:GITHUB|CYPRESS|VERCEL|NETLIFY|RUNNER|npm|JEST|VITEST)_\w*")


ENV_DESTRUCTURE = re.compile(r"\}\s*=\s*(?:process\.env|import\.meta\.env)\b")


def reads_project_env(repo: Repo) -> bool:
    """A named read of a non-built-in variable. Passing the whole environment on (env: process.env,
    os.environ.copy()) is not a sign of a .env file."""
    for f in repo.code_files():
        if ENV_DESTRUCTURE.search(f.code):
            return True
        for m in ENV_READ.finditer(f.code):
            name = next((g for g in m.groups() if g), None)
            if name and not BUILTIN_ENV.fullmatch(name):
                return True
    return False


def gitignore_ignores(repo: Repo, rel: str) -> bool:
    """Best-effort .gitignore matching for a non-git checkout: the .gitignore files above rel."""
    parts = rel.split("/")
    ignored = False
    for depth in range(len(parts)):
        base = "/".join(parts[:depth])
        gi = repo.by_path.get(f"{base}/.gitignore".lstrip("/"))
        if not gi:
            continue
        sub = "/".join(parts[depth:])
        for raw in gi.lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            negate = line.startswith("!")
            pat = line[1:] if negate else line
            if pat.endswith("/"):
                continue
            anchored = pat.startswith("/") or "/" in pat.rstrip("/")[:-1]
            pat = pat.lstrip("/")
            if pat.startswith("**/"):
                pat, anchored = pat[3:], False
            target = sub if anchored else parts[-1]
            if fnmatch.fnmatchcase(target, pat):
                ignored = not negate
    return ignored


def s05_env_not_ignored(repo: Repo, rule: Rule) -> list[Finding]:
    env_files = [p for p in repo.paths if ENV_NAME.fullmatch(p.rsplit("/", 1)[-1])]
    if not env_files and not reads_project_env(repo):
        return []
    # Check `.env` itself next to every env file (a rule for .env.local alone doesn't cover it),
    # plus the real non-example files.
    candidates = {".env"} | {p.rsplit("/", 1)[0] + "/.env" if "/" in p else ".env" for p in env_files}
    candidates |= {p for p in env_files if not ENV_EXAMPLE.search(p.rsplit("/", 1)[-1])}
    if repo.is_git:
        # --no-index: judge the rules themselves; a tracked file is never "ignored" otherwise (S03 covers it).
        ignored = repo.git_ignored(sorted(candidates), no_index=True)
        exposed = sorted(candidates - ignored)
        how = "git check-ignore --no-index"
    else:
        exposed = sorted(p for p in candidates if not gitignore_ignores(repo, p))
        how = ".gitignore rules"
    if not exposed:
        return []
    gi = ".gitignore" if ".gitignore" in repo.path_set else ".gitignore (missing)"
    return [rule.hit(
        repo, gi, f"{how}: {', '.join(exposed[:5])} would not be ignored",
        "One `git add .` commits the env file, and every key in it goes to everyone with repo access and stays "
        "in history.",
        "Add `.env*` and `!.env.example` to .gitignore.",
        verify="git check-ignore -v .env",
    )]


SERVICE_REF = re.compile(r"SERVICE_ROLE|service_role|sb_secret_|SUPABASE_SECRET_KEY")


STRING_LITERAL = re.compile(r"""(["'`])((?:\\.|(?!\1).)*)\1""")


def _in_prose_string(f: SourceFile, offset: int) -> bool:
    """True when offset sits inside a quoted string with spaces in it: an error message that names
    the variable, like "Account management needs SUPABASE_SECRET_KEY on the server." A real key
    or a real reference never has spaces around it."""
    n = f.line_at(offset)
    start = offset - (f.text.rfind("\n", 0, offset) + 1)
    for m in STRING_LITERAL.finditer(f.line(n)):
        if m.start(2) <= start < m.end(2):
            return bool(re.search(r"\s", m.group(2)))
    return False


def s06_service_role_in_client(repo: Repo, rule: Rule) -> list[Finding]:
    out = []
    for f in repo.code_files():
        kind = f.client_kind
        refs = SERVICE_REF.finditer(f.code) if kind else ()
        m = next((r for r in refs if not _in_prose_string(f, r.start())), None)
        if not m:
            continue
        n = f.line_at(m.start())
        if kind == "directive":
            why = ("Everything in a 'use client' file ships to the browser; with the service-role key any visitor "
                   "bypasses RLS and can read or delete every row.")
            sev = "P0"
        else:
            why = ("Confirm this file never ships to the browser: if the component is bundled for the client, the "
                   "service-role key bypasses RLS for every visitor.")
            sev = "P1"
        out.append(rule.hit(
            repo, f.where(n), f.evidence(n), why,
            "Create the service-role client only in server code (route handler, server action, edge function) with "
            "`import 'server-only'`; browser code uses the anon or publishable key.", severity=sev,
        ))
    return out


def s07_browser_ai_key(repo: Repo, rule: Rule) -> list[Finding]:
    return per_file(
        rule, repo, repo.code_files(), re.compile(r"dangerouslyAllowBrowser\s*:\s*true"),
        "The AI provider key sits in JavaScript every visitor downloads, so anyone can copy it and bill your account.",
        "Call the model from a server route or edge function with the key in a server-only env var, and remove "
        "dangerouslyAllowBrowser.",
    )


CREATE_TABLE = re.compile(
    rf"^create\s+(?:(?:global\s+|local\s+)?(temp|temporary)\s+|unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?{SQL_QNAME}",
    re.I,
)
ENABLE_RLS = re.compile(
    rf"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?{SQL_QNAME}\s+enable\s+row\s+level\s+security", re.I
)


def s08_table_without_rls(repo: Repo, rule: Rule) -> list[Finding]:
    rls = set()
    for _f, _n, stmt in repo.sql_statements:
        for m in ENABLE_RLS.finditer(stmt):
            rls.add(sql_name(m.group(1)))
    out, seen = [], set()
    for f, n, stmt in repo.sql_statements:
        m = CREATE_TABLE.match(stmt)
        if not m or m.group(1):
            continue
        schema, table = sql_name(m.group(2))
        if schema != "public" or (schema, table) in rls or (schema, table) in seen:
            continue
        seen.add((schema, table))
        out.append(rule.hit(
            repo, f.where(n), first_line(stmt),
            f"Supabase serves every public table over its REST API with the anon key from your frontend, so without "
            f"RLS anyone can read and change every row of {table}.",
            f"Add `alter table public.{table} enable row level security;` and policies scoped to "
            "`(select auth.uid())`.",
        ))
    return out


CREATE_POLICY = re.compile(rf"^create\s+policy\s+(\"[^\"]+\"|[\w$]+)\s+on\s+{SQL_QNAME}", re.I)
POLICY_FOR = re.compile(r"\bfor\s+(select|insert|update|delete|all)\b", re.I)
POLICY_TO = re.compile(r"\bto\s+(.+?)(?=\busing\b|\bwith\s+check\b|$)", re.I | re.S)
USING_TRUE = re.compile(r"\busing\s*\(\s*\(?\s*true\s*\)?\s*\)", re.I)
CHECK_TRUE = re.compile(r"\bwith\s+check\s*\(\s*\(?\s*true\s*\)?\s*\)", re.I)
TRUSTED_ROLES = {"service_role", "postgres", "supabase_admin"}


def s09_policy_true(repo: Repo, rule: Rule) -> list[Finding]:
    out = []
    for f, n, stmt in repo.sql_statements:
        m = CREATE_POLICY.match(stmt)
        if not m:
            continue
        # Everything between the table name and the first using/with check: command and roles.
        head = re.split(r"\busing\b|\bwith\s+check\b", stmt[m.end():], maxsplit=1, flags=re.I)[0]
        cmd = (POLICY_FOR.search(head).group(1).lower() if POLICY_FOR.search(head) else "all")
        roles_m = POLICY_TO.search(head)
        roles = {r.strip().strip('"').lower() for r in roles_m.group(1).split(",")} if roles_m else {"public"}
        if roles <= TRUSTED_ROLES:
            continue
        table = sql_name(m.group(2))[1]
        policy = f"policy {m.group(1)} on {table} for {cmd}"
        if cmd != "select" and (USING_TRUE.search(stmt) or CHECK_TRUE.search(stmt)):
            out.append(rule.hit(
                repo, f.where(n), f"{policy} with (true)",
                f"Any visitor holding the anon key (it ships in your frontend) can {cmd} any row of {table}.",
                "Replace `true` with an ownership check such as `(select auth.uid()) = user_id` and scope the policy "
                "`to authenticated`.",
            ))
        elif cmd == "select" and USING_TRUE.search(stmt):
            out.append(rule.hit(
                repo, f.where(n), f"{policy} using (true)",
                f"Public read: anyone can read every row of {table}, which leaks data if any row belongs to one user.",
                "Confirm every row is meant to be public; otherwise use `using ((select auth.uid()) = user_id)`.",
                severity="P2",
            ))
    return out


CREATE_FUNC = re.compile(rf"^create\s+(?:or\s+replace\s+)?(?:function|procedure)\s+{SQL_QNAME}\s*\(", re.I)
SECURITY_DEFINER = re.compile(r"\bsecurity\s+definer\b", re.I)
SET_SEARCH_PATH = re.compile(r"\bset\s+search_path\b", re.I)
RETURNS_TRIGGER = re.compile(r"\breturns\s+(?:event_)?trigger\b", re.I)
REVOKE_FUNC = re.compile(
    rf"revoke\s+(?:all(?:\s+privileges)?|execute)\s+on\s+(?:function|procedure|routine)\s+{SQL_QNAME}\s*(?:\([^)]*\))?\s+from\s+([^;]*)",
    re.I,
)
REVOKE_ALL_FUNCS = re.compile(
    r"revoke\s+(?:all(?:\s+privileges)?|execute)\s+on\s+(?:all\s+)?(?:functions|routines)\b[^;]*\bfrom\s+([^;]*)", re.I
)


def s10_security_definer(repo: Repo, rule: Rule) -> list[Finding]:
    revoked, revoke_all = set(), False
    for _f, _n, stmt in repo.sql_statements:
        for m in REVOKE_FUNC.finditer(stmt):
            if re.search(r"\b(?:public|anon)\b", m.group(2), re.I):
                revoked.add(sql_name(m.group(1)))
        for m in REVOKE_ALL_FUNCS.finditer(stmt):
            if re.search(r"\b(?:public|anon)\b", m.group(1), re.I):
                revoke_all = True
    out = []
    for f, n, stmt in repo.sql_statements:
        m = CREATE_FUNC.match(stmt)
        if not m:
            continue
        header = _SQL_BODY.sub(" ", stmt)
        schema, name = sql_name(m.group(1))
        if schema != "public" or not SECURITY_DEFINER.search(header):
            continue
        # Trigger functions can't be called over RPC, so only the search_path check applies.
        if not RETURNS_TRIGGER.search(header) and not revoke_all and (schema, name) not in revoked:
            out.append(rule.hit(
                repo, f.where(n), first_line(stmt),
                f"PostgREST exposes public functions as /rest/v1/rpc/{name}, and security definer runs with the "
                "owner's rights, so the anon key can call it and skip RLS.",
                f"Add `revoke execute on function public.{name} from public, anon;` (grant to authenticated if "
                "needed) or move it to a private schema.",
            ))
        if not SET_SEARCH_PATH.search(header):
            out.append(rule.hit(
                repo, f.where(n), f"{first_line(stmt)} (no set search_path)",
                "Without a fixed search_path a caller can shadow the tables or functions it uses and run code with "
                "the owner's rights.",
                "Add `set search_path = ''` to the function and schema-qualify every name inside it.",
                severity="P2",
            ))
    return out


CREATE_VIEW = re.compile(
    rf"^create\s+(?:or\s+replace\s+)?(?:(temp|temporary)\s+)?(?:recursive\s+)?view\s+(?:if\s+not\s+exists\s+)?{SQL_QNAME}",
    re.I,
)
SECURITY_INVOKER = re.compile(r"security_invoker\s*(?:=\s*([\w']+))?", re.I)
ALTER_VIEW = re.compile(rf"^alter\s+view\s+(?:if\s+exists\s+)?{SQL_QNAME}\s+set\s*\(([^)]*)\)", re.I)


def invoker_on(text: str) -> bool:
    m = SECURITY_INVOKER.search(text)
    return bool(m) and (m.group(1) is None or m.group(1).strip("'").lower() in ("true", "on", "yes", "1"))


def s11_view_without_invoker(repo: Repo, rule: Rule) -> list[Finding]:
    fixed = set()
    for _f, _n, stmt in repo.sql_statements:
        m = ALTER_VIEW.match(stmt)
        if m and invoker_on(m.group(2)):
            fixed.add(sql_name(m.group(1)))
    out = []
    for f, n, stmt in repo.sql_statements:
        m = CREATE_VIEW.match(stmt)
        if not m or m.group(1):
            continue
        schema, name = sql_name(m.group(2))
        head = re.split(r"\bas\b", stmt, maxsplit=1, flags=re.I)[0]
        if schema != "public" or invoker_on(head) or (schema, name) in fixed:
            continue
        out.append(rule.hit(
            repo, f.where(n), first_line(stmt),
            f"Views run with their owner's rights by default, so {name} returns rows that RLS would hide from the "
            "caller, to anyone with the anon key.",
            f"Recreate it with `create view public.{name} with (security_invoker = true) as ...` or run "
            f"`alter view public.{name} set (security_invoker = true);`.",
        ))
    return out


BUCKET_INSERT = re.compile(r"^insert\s+into\s+storage\s*\.\s*buckets\s*(?:\(([^)]*)\))?\s*values\s*(.*)$", re.I | re.S)
BUCKET_UPDATE = re.compile(r"update\s+storage\s*\.\s*buckets\s+set\s+[^;]*\bpublic\s*=\s*true", re.I)
BUCKET_JS = re.compile(r"\b(?:createBucket|updateBucket)\s*\(")
BUCKET_WHY = ("Every file in a public bucket is readable by anyone with its URL; one public bucket leaked 13,000 "
              "ID documents.")
BUCKET_FIX = ("Make the bucket private (`update storage.buckets set public = false where id = '...'`) and serve files "
              "with createSignedUrl; keep public only for files meant for everyone.")


def _tuples(values: str) -> list[str]:
    out, i = [], 0
    while True:
        i = values.find("(", i)
        if i < 0:
            return out
        end = matching_brace(values, i)
        out.append(values[i + 1:end - 1])
        i = end


def _public_buckets_in_insert(stmt: str) -> list[str]:
    m = BUCKET_INSERT.match(stmt)
    if not m:
        return []
    values = re.split(r"\bon\s+conflict\b", m.group(2), maxsplit=1, flags=re.I)
    names = []
    cols = [c.strip().strip('"').lower() for c in m.group(1).split(",")] if m.group(1) else []
    for tup in _tuples(values[0]):
        vals = split_top_level(tup)
        if "public" in cols:
            idx = cols.index("public")
            is_public = idx < len(vals) and vals[idx].strip().lower() in ("true", "'true'", "'t'")
        else:
            is_public = any(v.strip().lower() == "true" for v in vals)
        if is_public:
            names.append(vals[0].strip().strip("'") if vals else "?")
    if len(values) > 1 and re.search(r"\bpublic\s*=\s*true\b", values[1], re.I) and not names:
        names.append("(on conflict update)")
    return names


def s12_public_bucket(repo: Repo, rule: Rule) -> list[Finding]:
    out = []
    for f, n, stmt in repo.sql_statements:
        for name in _public_buckets_in_insert(stmt):
            out.append(rule.hit(repo, f.where(n), f"storage.buckets insert: bucket {name} with public = true",
                                BUCKET_WHY, BUCKET_FIX))
        if BUCKET_UPDATE.search(stmt):
            out.append(rule.hit(repo, f.where(n), first_line(stmt), BUCKET_WHY, BUCKET_FIX))
    for f in repo.code_files():
        for m in BUCKET_JS.finditer(f.code):
            call = f.code[m.end() - 1:matching_brace(f.code, m.end() - 1, 600)]
            if re.search(r"\bpublic\s*:\s*true\b", call):
                n = f.line_at(m.start())
                out.append(rule.hit(repo, f.where(n), f.evidence(n) + " … public: true", BUCKET_WHY, BUCKET_FIX))
    for f in repo.files:
        if f.name == "config.toml" and "supabase" in f.rel:
            section = ""
            for i, line in enumerate(f.lines, 1):
                sm = re.match(r"\s*\[storage\.buckets\.([\w\-]+)\]", line)
                if sm:
                    section = sm.group(1)
                elif line.strip().startswith("["):
                    section = ""
                elif section and re.match(r"\s*public\s*=\s*true\b", line):
                    out.append(rule.hit(repo, f.where(i), f"[storage.buckets.{section}] public = true",
                                        BUCKET_WHY, BUCKET_FIX))
    return out


FIREBASE_OPEN = re.compile(
    r"allow\s+read\s*,\s*write\s*:\s*if\s+true\b|allow\s+write\s*:\s*if\s+true\b|allow\s+(?:read\s*,\s*)?write\s*;"
    r"|if\s+request\.time\s*<\s*timestamp\.date\("
)


def s13_firebase_open(repo: Repo, rule: Rule) -> list[Finding]:
    fix = ("Require sign-in and ownership, e.g. `allow read, write: if request.auth != null && request.auth.uid == "
           "userId;`, then `firebase deploy --only firestore:rules,storage`.")
    out = []
    for f in repo.files:
        if f.ext == ".rules" and not f.is_test:
            m = FIREBASE_OPEN.search(f.code)
            if m:
                n = f.line_at(m.start())
                test_mode = "request.time" in m.group(0)
                why = ("Test-mode rules let anyone with your Firebase config (it ships in the app) read and write "
                       "everything until the date passes." if test_mode else
                       "Anyone with your Firebase config (it ships in the app) can read or overwrite this data.")
                out.append(rule.hit(repo, f.where(n), f.evidence(n), why, fix))
        elif f.name == "database.rules.json":
            try:
                rules = json.loads(strip_comments(f.text, ".json")).get("rules", {})
            except (ValueError, AttributeError):
                rules = {}
            if not isinstance(rules, dict):
                continue
            for key in (".read", ".write"):
                if rules.get(key) in (True, "true"):
                    idx = f.text.find(f'"{key}"')
                    n = f.line_at(idx) if idx >= 0 else 1
                    out.append(rule.hit(
                        repo, f.where(n), f.evidence(n),
                        "The whole Realtime Database is open at the root, so anyone with the project URL can "
                        f"{'read' if key == '.read' else 'overwrite'} every record.",
                        "Set root `.read`/`.write` to false and grant access per path with `auth != null && "
                        "auth.uid === $uid`.",
                    ))
    return out


WRITE_CALL = re.compile(r"\.(?:update|upsert|insert)\s*\(|\b(?:updateDoc|setDoc)\s*\(")
LIMIT_KEY = re.compile(
    r"(?:[{,]\s*)[\"']?(role|is_admin|isAdmin|admin|credits|balance|plan|tier|usage|usage_count|quota|limit|"
    r"subscription_status|stripe_customer_id|verified)[\"']?(?=\s*[:,}])"
)
CHAT_ROLE = re.compile(r"\bcontent\s*:|\brole\s*:\s*[\"'](?:user|assistant|system|tool)[\"']")


def s14_client_writes_limits(repo: Repo, rule: Rule) -> list[Finding]:
    out = []
    for f in repo.code_files():
        if not f.client_kind:
            continue
        hits = []
        for m in WRITE_CALL.finditer(f.code):
            open_at = m.end() - 1
            args = f.code[open_at:matching_brace(f.code, open_at, 800)]
            if "{" not in args:
                continue
            keys = [k.group(1) for k in LIMIT_KEY.finditer(args)]
            # A chat log row ({ role: 'user', content }) is not a privilege field.
            keys = [k for k in keys if not (k == "role" and CHAT_ROLE.search(args))]
            if keys:
                hits.append((f.line_at(m.start()), keys))
        if hits:
            n, keys = hits[0]
            more = f" ({len(hits)} such writes in this file)" if len(hits) > 1 else ""
            out.append(rule.hit(
                repo, f.where(n), f"{f.evidence(n)} [writes {', '.join(sorted(set(keys)))}]{more}",
                "A signed-in user can repeat this call from the browser console with their own values, resetting "
                "their usage cap or granting themselves a paid plan or admin role.",
                "Make those columns server-writable only (`revoke update (credits, role) on table public.profiles "
                "from authenticated;`) or move the write to a server function that checks the user first.",
            ))
    return out


STORAGE_SET = re.compile(r"\b(?:localStorage|sessionStorage)\.setItem\s*\(([^\n]*)")
TOKEN_WORDS = frozenset(("token", "tokens", "jwt", "session", "auth", "refresh"))


def _words(text: str) -> set[str]:
    return {w.lower() for w in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])", text)}


def s15_token_in_storage(repo: Repo, rule: Rule) -> list[Finding]:
    return per_file(
        rule, repo, repo.code_files(), STORAGE_SET,
        "Any script on the page (an XSS bug, a compromised npm package, a browser extension) can read web storage "
        "and replay the token as the user.",
        "Keep session tokens in httpOnly, Secure, SameSite cookies set by the server (for Supabase, @supabase/ssr "
        "cookie storage) instead of localStorage.",
        keep=lambda f, m: bool(_words(m.group(1)) & TOKEN_WORDS),
    )


XSS_SINK = re.compile(
    r"dangerouslySetInnerHTML|\bv-html\b|\{@html\b|\.(?:inner|outer)HTML\s*=(?!=)|insertAdjacentHTML\s*\(|"
    r"document\.write(?:ln)?\s*\("
)
SANITIZER = re.compile(r"DOMPurify|sanitize|\bxss\(|escapeHtml|escHtml|htmlEscape|escape_html|\besc\(", re.I)
STATIC_MARKUP = re.compile(r"""\s*(?:`[^`$]*`|"[^"\n]*"|'[^'\n]*')\s*(?:;|\n|$)""")


CONSTANT_HTML = re.compile(r"""\s*=\s*\{\{\s*__html\s*:\s*(?:[A-Za-z_$][\w$]*|"[^"$]*"|'[^'$]*')\s*,?\s*\}\}""")


def _real_xss_sink(f: SourceFile, m: re.Match) -> bool:
    n = f.line_at(m.start())
    if m.group(0) == "dangerouslySetInnerHTML":
        if "application/ld+json" in f.window(n, 3, 3):
            return False  # JSON-LD structured data is the common legitimate use
        tag = f.code[f.code.rfind("<", 0, m.start()):m.start()]
        if re.match(r"<(?:script|style)\b", tag) and CONSTANT_HTML.match(f.code, m.end()):
            return False
    if m.group(0).endswith("=") and STATIC_MARKUP.match(f.code, m.end()):
        return False  # a literal with nothing interpolated, including el.innerHTML = ''
    return True


def s16_xss_sink(repo: Repo, rule: Rule) -> list[Finding]:
    return per_file(
        rule, repo, repo.code_files(), XSS_SINK,
        "If user-controlled text ever reaches this HTML, an attacker's script runs in your visitors' sessions and "
        "can act as them.",
        "Render the text as children instead of HTML, or sanitize it first with DOMPurify.sanitize(html).",
        severity_for=lambda f: "P2" if SANITIZER.search(f.code) else "P1",
        keep=_real_xss_sink,
    )


STRIPE_EVENT = re.compile(
    r"checkout\.session\.completed|payment_intent\.succeeded|invoice\.paid|invoice\.payment_succeeded|"
    r"customer\.subscription\."
)
WEBHOOK_VERIFIED = re.compile(
    r"construct_?event(?:_?async)?|webhooks\.signature|verify_?header|stripe-signature|verify\w*(?:webhook|signature)",
    re.I,
)
REQUEST_HANDLER = re.compile(
    r"\b(?:req|request)\b|NextRequest|\bRequest\b|export\s+(?:async\s+)?function\s+POST|\.post\s*\(|Deno\.serve|"
    r"\bserve\s*\(|@app\.(?:route|post)|APIRouter|def\s+\w+\s*\(\s*request"
)


def s17_unverified_webhook(repo: Repo, rule: Rule) -> list[Finding]:
    out = []
    for f in repo.code_files():
        if "webhook" not in f.rel.lower() and "webhook" not in f.code.lower():
            continue
        m = STRIPE_EVENT.search(f.code)
        # Handler modules that only receive an already-verified event have no request object.
        if not m or WEBHOOK_VERIFIED.search(f.code) or not REQUEST_HANDLER.search(f.code):
            continue
        n = f.line_at(m.start())
        out.append(rule.hit(
            repo, f.where(n), f.evidence(n),
            "Anyone can POST a fake 'payment succeeded' event to this URL and unlock the product for free.",
            "Verify the signature on the raw body before trusting it: `stripe.webhooks.constructEvent(await "
            "req.text(), req.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET)`.",
        ))
    return out


SQL_CALL = r"(?:\.|\b)(?:query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe|unsafe)\s*\(\s*"
SQL_TEMPLATE = re.compile(SQL_CALL + r"`([^`]{0,2000})`")
# A literal followed by "+ name", not by another literal (that is just a long string split in two).
SQL_CONCAT = re.compile(SQL_CALL + r"""(["'])((?:(?!\1)[^\n]){0,500})\1\s*\+\s*(?!["'`])""")
SQL_PY_FSTRING = re.compile(r"""\.execute(?:many)?\s*\(\s*(?:[rR]?[fF]|[fF][rR])("{3}|'{3}|"|')(.{0,2000}?)\1""", re.S)
SQL_PY_FORMAT = re.compile(r"""\.execute(?:many)?\s*\(\s*("[^"\n]*"|'[^'\n]*')\s*(%|\.format\()""")
SQL_VERB = re.compile(r"\b(?:select|insert|update|delete)\b", re.I)
SQL_CLAUSE = re.compile(r"\b(?:from|into|set|where|values)\b", re.I)
# Where an interpolated piece is a value (a parameter would work) rather than a table or column name.
SQL_VALUE_POSITION = re.compile(r"(?:[=<>]|\blike|\bin\s*\(|\bvalues\s*\(|\blimit|\boffset|\bbetween)\s*['\"%(]*$", re.I)
CONSTANT_NAME = re.compile(r"[A-Z_][A-Z0-9_]*")


def _looks_like_sql(text: str) -> bool:
    return bool(SQL_VERB.search(text) and SQL_CLAUSE.search(text)) or bool(re.search(r"\bwhere\b\s+\w+\s*=", text, re.I))


def _interpolates_value(sql: str, marker: re.Pattern) -> bool:
    """True when some interpolation sits where a bound parameter belongs and isn't an ALL_CAPS constant."""
    for m in marker.finditer(sql):
        if CONSTANT_NAME.fullmatch(m.group(1).strip()):
            continue
        if SQL_VALUE_POSITION.search(sql[max(0, m.start() - 30):m.start()]):
            return True
    return False


JS_INTERP = re.compile(r"\$\{([^}]*)\}")
PY_INTERP = re.compile(r"(?<!\{)\{([^{}]*)\}(?!\})")
PY_PERCENT = re.compile(r"%(?:\((\w+)\))?[sdrf]|\{(\w*)\}")


def s18_sql_interpolation(repo: Repo, rule: Rule) -> list[Finding]:
    out = []
    for f in repo.code_files():
        spots = [m.start() for m in SQL_TEMPLATE.finditer(f.code)
                 if _looks_like_sql(m.group(1)) and _interpolates_value(m.group(1), JS_INTERP)]
        spots += [m.start() for m in SQL_CONCAT.finditer(f.code)
                  if _looks_like_sql(m.group(2)) and SQL_VALUE_POSITION.search(m.group(2))]
        if f.ext == ".py":
            spots += [m.start() for m in SQL_PY_FSTRING.finditer(f.code)
                      if _looks_like_sql(m.group(2)) and _interpolates_value(m.group(2), PY_INTERP)]
            for m in SQL_PY_FORMAT.finditer(f.code):
                sql = m.group(1)
                if _looks_like_sql(sql) and any(SQL_VALUE_POSITION.search(sql[:p.start()]) for p in PY_PERCENT.finditer(sql)):
                    spots.append(m.start())
        if not spots:
            continue
        n = f.line_at(min(spots))
        more = f" ({len(spots)} in this file)" if len(spots) > 1 else ""
        out.append(rule.hit(
            repo, f.where(n), f.evidence(n) + more,
            "Whoever controls the interpolated value can rewrite the query and read or delete any table.",
            "Pass values as parameters: `db.query('select * from users where id = $1', [id])`, a tagged template "
            "(sql`... ${id}`), `$queryRaw` instead of `$queryRawUnsafe`, or `cursor.execute(sql, params)`.",
        ))
    return out


CORS_OPEN = re.compile(
    r"Access-Control-Allow-Origin[\"'\]]*\s*[:,=]?\s*(?:[\"']value[\"']\s*:\s*)?[\"']?\*(?![\w*/.])"
    r"|\bcors\(\s*\)|\borigin\s*:\s*[\"']\*[\"']|\borigin\s*:\s*true\b",
    re.I,
)
CORS_CREDENTIALS = re.compile(r"credentials\s*:\s*true|Access-Control-Allow-Credentials[\"'\]]*\s*[:,=]?\s*[\"']?true", re.I)
CORS_CONFIG_NAMES = frozenset(("vercel.json", "netlify.toml", "_headers", "nginx.conf", "serverless.yml", "firebase.json"))


def s19_cors_open(repo: Repo, rule: Rule) -> list[Finding]:
    # vite.config server.cors only affects the local dev server.
    files = [f for f in repo.files if (f.is_code or f.name in CORS_CONFIG_NAMES) and not f.name.startswith("vite.config.")]
    out = []
    for f in files:
        m = CORS_OPEN.search(f.code)
        if not m:
            continue
        n = f.line_at(m.start())
        creds = bool(CORS_CREDENTIALS.search(f.code))
        why = ("With credentials allowed, any site the user visits can send logged-in requests as them and read the "
               "answers." if creds else
               "Any website can call this endpoint from a visitor's browser and read the response: fine for a truly "
               "public API, a leak for anything that trusts cookies or network location.")
        out.append(rule.hit(
            repo, f.where(n), f.evidence(n), why,
            "List the exact origins you serve (`origin: ['https://yourapp.com']`) and drop credentials unless the "
            "endpoint needs cookies.", severity="P0" if creds else None,
        ))
    return out


def _vite_build_sourcemap(f: SourceFile) -> int | None:
    m = re.search(r"\bbuild\s*:\s*\{", f.code)
    if not m:
        return None
    block_end = matching_brace(f.code, m.end() - 1)
    s = re.search(r"\bsourcemap\s*:\s*true\b", f.code[m.end():block_end])
    return f.line_at(m.end() + s.start()) if s else None


def s20_debug_in_prod(repo: Repo, rule: Rule) -> list[Finding]:
    hits: list[tuple[SourceFile, int, str]] = []
    for f in repo.files:
        if f.is_test:
            continue
        name = f.name
        m = None
        if name.startswith("next.config."):
            m = re.search(r"productionBrowserSourceMaps\s*:\s*true", f.code)
            kind = "source maps"
        elif name.startswith("vite.config."):
            n = _vite_build_sourcemap(f)
            if n:
                hits.append((f, n, "source maps"))
            continue
        elif "webpack" in name and f.ext in JS_EXTS:
            if "prod" in name or re.search(r"mode\s*:\s*[\"']production[\"']", f.code):
                m = re.search(r"devtool\s*:\s*[\"']source-map[\"']", f.code)
            kind = "source maps"
        elif f.ext == ".py" and re.match(r"settings.*\.py$", name) and not re.search(r"dev|local|test", name):
            m = re.search(r"(?m)^\s*DEBUG\s*=\s*True\b", f.code)
            kind = "debug"
        elif f.ext == ".py":
            m = re.search(r"\.run\([^)\n]*\bdebug\s*=\s*True", f.code)
            kind = "debug"
        else:
            continue
        if m:
            hits.append((f, f.line_at(m.start()), kind))
    out = []
    for f, n, kind in hits:
        why = ("Public source maps hand anyone your original source, comments and internal endpoints."
               if kind == "source maps" else
               "Debug mode shows stack traces, settings and sometimes secrets on every error page, and Werkzeug's "
               "debugger allows remote code execution.")
        fix = ("Remove it or use `sourcemap: 'hidden'` and upload maps to your error tracker instead."
               if kind == "source maps" else
               "Read it from the environment (`DEBUG = os.environ.get('DEBUG') == '1'`) and keep it off in production.")
        out.append(rule.hit(repo, f.where(n), f.evidence(n), why, fix))
    return out


WEAK_HASH = re.compile(r"createHash\(\s*[\"'](?:md5|sha1|sha256)[\"']|hashlib\.(?:md5|sha1|sha256)\(")
PASSWORD_WORD = re.compile(r"password|passwd|pwd", re.I)
RESET_IDENT = re.compile(r"reset[_\-]?password\w*|password[_\-]?reset\w*|forgot[_\-]?password\w*", re.I)


def s21_weak_password_hash(repo: Repo, rule: Rule) -> list[Finding]:
    def near_password(f: SourceFile, m: re.Match) -> bool:
        # Hashing a reset *token* with sha256 is fine; the word "password" in its name is not a password.
        window = RESET_IDENT.sub(" ", f.window(f.line_at(m.start()), 3, 3))
        return bool(PASSWORD_WORD.search(window))

    return per_file(
        rule, repo, repo.code_files(), WEAK_HASH,
        "MD5 and SHA hashes are built to be fast, so a leaked user table can be cracked at billions of guesses per "
        "second.",
        "Hash passwords with argon2, scrypt or bcrypt (`await argon2.hash(password)`), or let your auth provider "
        "store them.", keep=near_password,
    )


SERVER_ROUTE = re.compile(r"(?:^|/)(?:src/)?(?:app|pages)/api/|(?:^|/)supabase/functions/")
SERVER_DEPS = ("express", "fastify", "hono", "koa", "flask", "fastapi", "django")
RATE_LIMIT_DEPS = ("express-rate-limit", "rate-limiter-flexible", "@upstash/ratelimit", "@arcjet/*", "hono-rate-limiter",
                   "@nestjs/throttler", "slowapi", "flask-limiter", "django-ratelimit")
# Deno edge functions import limiters by URL, and some apps write their own.
RATE_LIMIT_CODE = re.compile(r"@upstash/ratelimit|rate-limiter-flexible|@arcjet/|rate[_\-]?limit", re.I)


def s22_no_rate_limit(repo: Repo, rule: Rule) -> list[Finding]:
    routes = [p for p in repo.paths if SERVER_ROUTE.search(p) and not TEST_NAME.search(p)]
    servers = repo.deps_matching(SERVER_DEPS)
    if not routes and not servers:
        return []
    if repo.has_dep(*RATE_LIMIT_DEPS) or repo.first(RATE_LIMIT_CODE, repo.code_files()):
        return []
    where = f"{routes[0]}:1" if routes else repo.deps[servers[0]]
    what = (f"{len(routes)} server route files (e.g. {', '.join(routes[:3])})" if routes
            else f"server framework {', '.join(servers)}")
    return [rule.hit(
        repo, where, f"{what}; no rate-limit dependency or limiter found",
        "Anyone can script thousands of requests at your API and run up AI, email or database bills; Supabase "
        "Auth's built-in limits cover the auth endpoints only, not your own routes and functions.",
        "Put a per-user and per-IP limit in front of costly routes, e.g. @upstash/ratelimit in route handlers and "
        "edge functions (Supabase Auth's limits don't cover them).",
    )]


BOT_PROTECTION = re.compile(r"turnstile|hcaptcha|recaptcha|arcjet|botid|friendly-challenge|captcha", re.I)


def s23_no_bot_protection(repo: Repo, rule: Rule) -> list[Finding]:
    if repo.first(BOT_PROTECTION, repo.pattern_files(), use_code=False):
        return []
    return [rule.hit(
        repo, repo.signup_where or ".", f"signup at {repo.signup_where}; no captcha or bot-protection signature found",
        "Bots can create thousands of fake accounts, burning your email quota, free-tier credits and reputation.",
        "Add Cloudflare Turnstile or hCaptcha to the signup form and verify the token server-side (Supabase: enable "
        "Auth > Bot and Abuse Protection and pass captchaToken to signUp).",
    )]


REDIRECT_SINK = re.compile(
    r"\bredirect\s*\(|router\.(?:push|replace)\s*\(|location\.href\s*=(?!=)|window\.location\s*=(?!=)|"
    r"location\.(?:assign|replace)\s*\(|res\.redirect\s*\(|RedirectResponse\s*\("
)
REDIRECT_PARAMS = r"next|redirect|redirectTo|redirect_to|returnTo|return_to|returnUrl|callbackUrl|continue|url"
PARAM_READ = re.compile(
    rf"""(?:searchParams|params|query|args|GET|URLSearchParams\([^)]*\))\s*(?:\.get\(\s*|\.|\[\s*)["']?({REDIRECT_PARAMS})\b["']?"""
    rf"""|\{{[^}}\n]*\b({REDIRECT_PARAMS})\b[^}}\n]*\}}\s*=\s*(?:await\s+)?(?:[\w.]+\.)?(?:query|searchParams|params|args)\b"""
)
ASSIGNED_VAR = re.compile(r"(?:const|let|var)\s+(\w+)\s*=|^\s*(\w+)\s*=")
REDIRECT_GUARD = re.compile(
    r"startsWith\(\s*[\"'`]/|new URL\(|safe\w*(?:redirect|url|path)|is(?:Relative|Internal|Local|Safe)\w*", re.I
)


def s24_open_redirect(repo: Repo, rule: Rule) -> list[Finding]:
    out = []
    for f in repo.code_files():
        lines = f.code.split("\n")
        hit = None
        for i, line in enumerate(lines):
            read = PARAM_READ.search(line)
            if not read:
                continue
            var_m = ASSIGNED_VAR.search(line)
            names = {var_m.group(1) or var_m.group(2)} if var_m else set()
            if read.group(2):
                names.add(read.group(2))
            sink_at = None
            for j in range(max(0, i - 2), min(len(lines), i + 3)):
                if REDIRECT_SINK.search(lines[j]):
                    sink_at = j
                    break
            if sink_at is None and names:
                for j in range(i + 1, min(len(lines), i + 20)):
                    sm = REDIRECT_SINK.search(lines[j])
                    if sm and any(re.search(rf"\b{re.escape(v)}\b", lines[j][sm.start():]) for v in names):
                        sink_at = j
                        break
            if sink_at is None:
                continue
            lo, hi = min(i, sink_at) - 5, max(i, sink_at) + 6
            if REDIRECT_GUARD.search("\n".join(lines[max(0, lo):hi])):
                continue
            hit = sink_at + 1
            break
        if hit:
            out.append(rule.hit(
                repo, f.where(hit), f.evidence(hit),
                "Attackers send your real login link with ?next=https://evil.example, so users land on a phishing "
                "page right after trusting your domain.",
                "Allow only same-site paths: `const safe = next?.startsWith('/') && !next.startsWith('//') ? next : '/'`.",
            ))
    return out


# --- L: legal and accessibility ----------------------------------------------

GOOGLE_FONTS = re.compile(r"fonts\.(?:googleapis|gstatic)\.com")
CSP_LINE = re.compile(r"(?:font|style|connect|default|script|img)-src|Content-Security-Policy", re.I)


def not_csp(f: SourceFile, m: re.Match) -> bool:
    """An origin listed in a CSP allowlist isn't a request; the tag or import that loads it is."""
    return not CSP_LINE.search(f.line(f.line_at(m.start())))


def l01_google_fonts(repo: Repo, rule: Rule) -> list[Finding]:
    return per_file(
        rule, repo, repo.web_files(), GOOGLE_FONTS,
        "Each page view sends the visitor's IP address to Google before any consent; a Munich court awarded €100 "
        "to one visitor for this in 2022.",
        "Self-host the font: `next/font/google` (downloads at build time), `@fontsource/<family>`, or woff2 files "
        "in public/.", attr="text", keep=not_csp,
    )


TRACKERS = {
    "Google tag (gtag / GTM / GA)": re.compile(
        r"\bgtag\s*\(|googletagmanager\.com|google-analytics\.com|"
        r"import\s*\{[^}]*\b(?:GoogleAnalytics|GoogleTagManager|sendGAEvent|sendGTMEvent)\b[^}]*\}\s*from\s*[\"']@next/third-parties/google"
    ),
    "Meta Pixel": re.compile(r"\bfbq\s*\(|connect\.facebook\.net"),
    "TikTok Pixel": re.compile(r"analytics\.tiktok\.com"),
    "LinkedIn Insight Tag": re.compile(r"snap\.licdn\.com"),
    "Mixpanel": re.compile(r"mixpanel", re.I),
    "Amplitude": re.compile(r"@amplitude/|amplitude-js|cdn\.amplitude\.com|\bamplitude\.(?:init|track|getInstance|add)\("),
    "Segment": re.compile(r"cdn\.segment\.com|@segment/analytics"),
    "PostHog": re.compile(r"posthog", re.I),
    "Heap": re.compile(r"heapanalytics|@heap/|\bheap\.(?:load|track|identify)\("),
}
CONSENT_TOOL = re.compile(
    r"cookieconsent|cookie-consent|klaro|osano|onetrust|cookiebot|termly|iubenda|usercentrics|\bc15t\b|"
    r"gtag\(\s*[\"']consent[\"']|opt_out_capturing_by_default|cookieless_mode|cookie-?banner|consent-?banner",
    re.I,
)


def found_trackers(repo: Repo) -> dict[str, tuple[SourceFile, int]]:
    found = {}
    for name, pattern in TRACKERS.items():
        for f in repo.web_files():
            m = next((m for m in pattern.finditer(f.code) if not_csp(f, m)), None)
            if m:
                found[name] = (f, f.line_at(m.start()))
                break
    return found


def l02_tracker_without_consent(repo: Repo, rule: Rule) -> list[Finding]:
    if repo.first(CONSENT_TOOL, repo.web_files()):
        return []
    return [
        rule.hit(
            repo, f.where(n), f"{name}: {f.evidence(n)}",
            f"{name} sets tracking cookies and sends personal data before the visitor agrees, which EU "
            "ePrivacy/GDPR rules forbid and several US state laws require an opt-out for.",
            f"Add a consent tool (vanilla-cookieconsent, c15t, Cookiebot) and load {name} only after opt-in, or "
            "switch to cookieless analytics (Plausible, Fathom, Vercel Analytics).",
        )
        for name, (f, n) in found_trackers(repo).items()
    ]


REPLAY_TOOLS = {
    "Hotjar": re.compile(r"hotjar", re.I),
    "FullStory": re.compile(r"@fullstory|fullstory\.com", re.I),
    "LogRocket": re.compile(r"logrocket", re.I),
    "Microsoft Clarity": re.compile(r"clarity\.ms|@microsoft/clarity"),
    "Mouseflow": re.compile(r"mouseflow", re.I),
    "Smartlook": re.compile(r"smartlook", re.I),
    "rrweb": re.compile(r"\brrweb\b"),
    "Sentry Session Replay": re.compile(r"replayIntegration\s*\(|new\s+(?:Sentry\.)?Replay\s*\("),
    "PostHog session recording": re.compile(
        r"disable_session_recording\s*:\s*false|session_recording\s*:\s*\{|startSessionRecording\s*\("
    ),
}
INPUT_MASKING = re.compile(r"maskAllInputs|maskAllText|mask_all_inputs|data-hj-suppress|fs-exclude|maskInputOptions")


def found_replay(repo: Repo) -> dict[str, tuple[SourceFile, int]]:
    found = {}
    for name, pattern in REPLAY_TOOLS.items():
        hit = repo.first(pattern, repo.web_files())
        if hit:
            found[name] = hit
    return found


def l03_session_replay(repo: Repo, rule: Rule) -> list[Finding]:
    masking = repo.first(INPUT_MASKING, repo.web_files())
    mask_note = (f"input masking found ({masking[0].where(masking[1])})" if masking
                 else "no input-masking option found")
    return [
        rule.hit(
            repo, f.where(n), f"{name}: {f.evidence(n)}; {mask_note}",
            "Recording keystrokes and clicks without consent can count as wiretapping under California's CIPA, with "
            "claimed damages of $5,000 per session.",
            "Mask all inputs and text (e.g. `replayIntegration({ maskAllText: true, blockAllMedia: true })`), load "
            "the recorder only after consent, and name it in the privacy policy.",
        )
        for name, (f, n) in found_replay(repo).items()
    ]


PAYMENT_DEPS = ("stripe", "@stripe/*", "lemonsqueezy", "@lemonsqueezy/*", "paddle", "@paddle/*")
URLISH = re.compile(r"""["'`]((?:https?://[^\s"'`]+)?/[^\s"'`]*)["'`]""")
LEGAL_PAGES = (
    # (slug, severity, path-word test, why)
    ("privacy", "P1", lambda w: w.startswith("privacy"),
     "App stores, payment processors and privacy laws (GDPR, CCPA) require a privacy policy that says what you "
     "collect and why."),
    ("terms", "P1", lambda w: w.startswith("terms") or w in ("tos", "eula"),
     "Without terms you have no stated rules to enforce against abusive users and no limit on your liability."),
    ("cookies", "P2", lambda w: w.startswith("cookie"),
     "You load trackers, and EU rules expect a cookie policy that lists each one and its purpose."),
    ("accessibility", "P2", lambda w: w.startswith("accessibility") or w == "a11y",
     "An accessibility statement is expected under the European Accessibility Act (in force since June 2025) and "
     "shows good faith against ADA demand letters."),
    ("refunds", "P2", lambda w: w.startswith("refund") or w == "returns",
     "Card networks and consumer law expect a stated refund policy, and without one refund requests become "
     "chargebacks."),
)


def _legal_words(repo: Repo) -> set[str]:
    words: set[str] = set()
    for f in repo.files:
        # Page files only: components/CookieBanner.tsx is not a cookie policy.
        if (f.user_facing or f.ext in (".md", ".html")) and "components/" not in f.rel and not f.is_test:
            words.update(path_words(f.rel))
    for f in repo.source_files():
        for m in URLISH.finditer(f.code):
            words.update(path_words(urlparse(m.group(1)).path))
    return words


def l04_legal_page_missing(repo: Repo, rule: Rule) -> list[Finding]:
    if not (repo.has_web or repo.has_native):
        return []
    words = _legal_words(repo)
    wanted = {"privacy", "terms", "accessibility"}
    if found_trackers(repo) or found_replay(repo):
        wanted.add("cookies")
    if repo.has_dep(*PAYMENT_DEPS):
        wanted.add("refunds")
    out = []
    for slug, sev, test, why in LEGAL_PAGES:
        if slug in wanted and not any(test(w) for w in words):
            hint = repo.route_hint(slug)
            out.append(rule.hit(
                repo, f"{hint} (missing)", f"no route, file or link containing '{slug}' found",
                why,
                f"Add {'an' if slug[0] in 'aeiou' else 'a'} {slug} page at {hint} and link it from the footer; an agent "
                "may draft it, a person (or a lawyer) approves the text.", severity=sev,
            ))
    return out


CHECKBOX_TAG = re.compile(r"<(?:input|Checkbox|checkbox|Switch)\b")
PRECHECKED = re.compile(
    r"(?<![\w:\-])(?:defaultChecked|checked)(?:\s*=\s*(?:\{\s*true\s*\}|[\"'](?:checked|true)[\"']))?(?=[\s/>])"
)
CONSENT_WORD = re.compile(r"newsletter|marketing|consent|agree|subscribe|terms|updates|offers", re.I)
CONSENT_STATE = re.compile(
    r"const\s*\[\s*(\w+)\s*,\s*\w+\s*\]\s*=\s*(?:React\.)?useState(?:<[^>]*>)?\(\s*true\s*\)"
    r"|(?:const|let)\s+(\w+)\s*=\s*ref\(\s*true\s*\)"
)
FORM_CONTROL = re.compile(r"<(?:input|Checkbox|checkbox|Switch|button|Button|select)\b|</label>|</form>")


def _consent_context(text: str, start: int, end: int) -> str:
    """Up to 3 lines around a tag, cut at the neighbouring form control so labels don't bleed over."""
    before_start = start
    for _ in range(4):
        before_start = text.rfind("\n", 0, max(0, before_start - 1)) + 1
        if before_start == 0:
            break
    before = text[before_start:start]
    cut = list(FORM_CONTROL.finditer(before))
    if cut:
        before = before[cut[-1].end():]
    after_end = end
    for _ in range(3):
        nxt = text.find("\n", after_end + 1)
        after_end = len(text) if nxt < 0 else nxt
    after = text[end:after_end]
    cut_after = FORM_CONTROL.search(after)
    if cut_after:
        after = after[:cut_after.start()]
    return before + text[start:end] + after


def l05_prechecked_consent(repo: Repo, rule: Rule) -> list[Finding]:
    out = []
    for f in repo.user_files():
        hit = None
        for m in CHECKBOX_TAG.finditer(f.code):
            tag = read_tag(f.code, m.start())
            if m.group(0) == "<input" and not re.search(r"type\s*=\s*[\"']checkbox[\"']", tag):
                continue
            if PRECHECKED.search(tag) and CONSENT_WORD.search(_consent_context(f.code, m.start(), m.start() + len(tag))):
                hit = f.line_at(m.start())
                break
        if hit is None:
            for m in CONSENT_STATE.finditer(f.code):
                if CONSENT_WORD.search(m.group(1) or m.group(2)):
                    hit = f.line_at(m.start())
                    break
        if hit:
            out.append(rule.hit(
                repo, f.where(hit), f.evidence(hit),
                "Consent from a pre-ticked box is not valid under GDPR (CJEU Planet49), so the list you build with it "
                "can't lawfully be mailed.",
                "Start the box unchecked (`defaultChecked={false}` / `useState(false)`) so the user opts in themselves.",
            ))
    return out


AGE_SIGNAL = re.compile(
    r"birth|\bdob\b|date_of_birth|age_verified|isAdult|age[_\-]?gate|minimum age|"
    r"\b(?:over|at least|older than)\s+1[3-8]\b|\b1[3-8]\s+(?:or older|years (?:of age|old|or older))",
    re.I,
)


def l06_no_age_check(repo: Repo, rule: Rule) -> list[Finding]:
    if repo.first(AGE_SIGNAL, repo.source_files()):
        return []
    return [rule.hit(
        repo, repo.signup_where or ".", f"signup at {repo.signup_where}; no age gate, birth date or minimum-age text found",
        "COPPA: under-13 users who sign up without verifiable parental consent expose you to fines of up to about "
        "$53,000 per violation.",
        "Decide the minimum age, state it in the terms, and add an age confirmation or birth-date check at signup.",
    )]


AI_DEPS = ("openai", "@anthropic-ai/sdk", "ai", "@ai-sdk/*", "langchain", "@langchain/*", "@google/generative-ai",
           "@google/genai", "replicate", "groq-sdk", "@mistralai/mistralai", "together-ai",
           # Python names (normalized)
           "anthropic", "langchain-*", "google-generativeai", "google-genai", "groq", "mistralai", "together")


def ai_deps(repo: Repo) -> list[str]:
    names = [n for n in AI_DEPS if not n.endswith("-*")]
    found = repo.deps_matching(names)
    found += sorted(d for d in repo.deps if d.startswith("langchain-"))
    return found


def l07_ai_disclosure(repo: Repo, rule: Rule) -> list[Finding]:
    found = ai_deps(repo)
    if not found:
        return []
    return [rule.hit(
        repo, repo.deps[found[0]], f"AI SDK dependencies: {', '.join(found[:6])}",
        "The EU AI Act (Art. 50) requires telling people when they chat with an AI or see AI-generated content, "
        "and an uncapped AI endpoint lets one user run up the bill.",
        "Label AI output and chatbots in the UI, cap spend per user (requests or tokens per day), and never present "
        "it as therapy, medical or legal advice.",
    )]


ACCOUNT_DELETION = re.compile(
    r"deleteUser|delete_user|deleteAccount|delete-account|delete[\s_]+(?:my\s+|your\s+|the\s+)?account|"
    r"closeAccount|removeAccount|close[\s_\-]account|remove[\s_\-]account",
    re.I,
)
DELETION_FIX = ("Add a 'Delete account' action that calls a server route running `supabase.auth.admin.deleteUser(id)` "
                "(service role, server-side) and deletes the user's rows.")


def has_account_deletion(repo: Repo) -> bool:
    return repo.first(ACCOUNT_DELETION, repo.source_files()) is not None


def l08_no_account_deletion(repo: Repo, rule: Rule) -> list[Finding]:
    if has_account_deletion(repo):
        return []
    return [rule.hit(
        repo, repo.signup_where or ".", f"signup at {repo.signup_where}; no account-deletion path found",
        "GDPR's right to erasure and CCPA let users demand deletion, and handling each request by hand doesn't "
        "scale or meet the deadlines.", DELETION_FIX,
    )]


IMG_TAG = re.compile(r"<(img|Image)(?=[\s/>])")
ALT_ATTR = re.compile(
    r"(?<![\w\-])(?::|v-bind:)?alt(?=\s*=|[\s/>}])|\{alt\}|accessibilityLabel|aria-label|aria-hidden|"
    r"role\s*=\s*[\"'](?:presentation|none)[\"']"
)
ICON_IMPORT = re.compile(r"import\s*\{[^}]*\bImage\b[^}]*\}\s*from\s*[\"'][^\"']*(?:lucide|icons|heroicons|phosphor|tabler)", re.S)


def l09_img_without_alt(repo: Repo, rule: Rule) -> list[Finding]:
    out = []
    for f in repo.user_files():
        icon_image = bool(ICON_IMPORT.search(f.code))
        missing = []
        for m in IMG_TAG.finditer(f.code):
            if m.group(1) == "Image" and icon_image:
                continue
            tag = read_tag(f.code, m.start())
            if "{..." in tag or ALT_ATTR.search(tag):
                continue  # a spread may carry alt; can't tell statically
            missing.append(f.line_at(m.start()))
        if missing:
            n = missing[0]
            more = f" ({len(missing)} images without alt in this file)" if len(missing) > 1 else ""
            out.append(rule.hit(
                repo, f.where(n), f.evidence(n) + more,
                "Screen-reader users hear nothing or the file name, which fails WCAG 1.1.1 and is the most common "
                "item in ADA demand letters.",
                "Add `alt` describing the image, or `alt=\"\"` if it is purely decorative.",
            ))
    return out


OUTLINE_NONE = re.compile(r"\boutline\s*:\s*[\"']?(?:none|0)\b|(?<![\w\-])(?<!\]:)outline-none\b")
FOCUS_REPLACEMENT = re.compile(
    r"(?:focus(?:-within)?|data-\[highlighted\]|data-highlighted):(?:ring|border|shadow|underline|bg-|outline-(?!none))"
)
STRING_AT = re.compile(r'"[^"\n]*"|\'[^\'\n]*\'|`[^`]*`')


def _outline_has_replacement(f: SourceFile, m: re.Match) -> bool:
    if f.is_style:
        open_at = f.code.rfind("{", 0, m.start())
        selector = f.code[f.code.rfind("}", 0, open_at) + 1:open_at]
        block = f.code[open_at:f.code.find("}", m.end())]
        return ":focus" in selector and bool(re.search(r"box-shadow|border|outline-offset", block))
    for s in STRING_AT.finditer(f.code, max(0, m.start() - 400), m.end() + 400):
        if s.start() <= m.start() < s.end():
            return bool(FOCUS_REPLACEMENT.search(s.group(0)))
    return False


def l10_focus_outline_removed(repo: Repo, rule: Rule) -> list[Finding]:
    files = [f for f in repo.design_files() if "focus-visible" not in f.code]
    return per_file(
        rule, repo, files, OUTLINE_NONE,
        "Keyboard users can't see which control has focus, which fails WCAG 2.4.7 and makes the site unusable "
        "without a mouse.",
        "Keep a visible focus style: `focus-visible:ring-2 focus-visible:ring-offset-2` (Tailwind) or "
        "`:focus-visible { outline: 2px solid currentColor }`.",
        keep=lambda f, m: not _outline_has_replacement(f, m),
    )


def _is_root_document(f: SourceFile) -> bool:
    return (f.ext in (".html", ".htm", ".astro") or re.fullmatch(r"layout\.(?:tsx|jsx|js|ts)", f.name) is not None
            or f.name.startswith("_document.") or f.name == "app.html")


def l11_html_without_lang(repo: Repo, rule: Rule) -> list[Finding]:
    out = []
    for f in repo.files:
        if f.is_test or f.is_doc or not _is_root_document(f):
            continue
        m = re.search(r"<html\b", f.code, re.I)
        if m and not re.search(r"(?<![\w\-])(?::)?lang\s*=", read_tag(f.code, m.start())):
            n = f.line_at(m.start())
            out.append(rule.hit(
                repo, f.where(n), f.evidence(n),
                "Without a page language screen readers use the wrong voice and pronunciation (WCAG 3.1.1) and "
                "browsers offer the wrong translation.",
                "Set the language on the root element: `<html lang=\"en\">`.",
            ))
    return out


EMAIL_DEPS = ("resend", "@sendgrid/mail", "nodemailer", "postmark", "mailgun.js", "@react-email/*", "loops",
              "mailchimp", "@mailchimp/*", "sendgrid")
UNSUBSCRIBE = re.compile(r"unsubscribe|List-Unsubscribe", re.I)


def l12_no_unsubscribe(repo: Repo, rule: Rule) -> list[Finding]:
    found = repo.deps_matching(EMAIL_DEPS)
    if not found or repo.first(UNSUBSCRIBE, repo.source_files()):
        return []
    return [rule.hit(
        repo, repo.deps[found[0]], f"email dependencies: {', '.join(found)}; no 'unsubscribe' anywhere",
        "CAN-SPAM requires a working unsubscribe link and a postal address in every marketing email, with "
        "penalties per message.",
        "Add an unsubscribe link and your postal address to marketing templates, send a List-Unsubscribe header, "
        "and honor opt-outs; purely transactional mail (receipts, password resets) is exempt.",
    )]


IAP_DEPS = ("react-native-purchases", "react-native-iap", "expo-iap", "expo-in-app-purchases", "cordova-plugin-purchase",
            "@capacitor-community/in-app-purchases", "@revenuecat/purchases-capacitor", "purchases_flutter",
            "in_app_purchase")
SUBSCRIPTION_CODE = re.compile(
    r"\bmode\s*[:=]\s*[\"']subscription[\"']|[\"']mode[\"']\s*:\s*[\"']subscription[\"']|"
    r"[\"']?\brecurring[\"']?\s*:\s*\{|subscriptions\.create\s*\("
)
RENEWAL_TERMS = re.compile(
    r"\brenews?\b|renewal|auto-renew|cancel anytime|per month|/mo\b|/month\b|billed (?:monthly|annually|yearly)|"
    r"per year|/year\b|/yr\b",
    re.I,
)


def l13_no_renewal_terms(repo: Repo, rule: Rule) -> list[Finding]:
    iap = repo.deps_matching(IAP_DEPS)
    hit = repo.first(SUBSCRIPTION_CODE, repo.code_files())
    if hit:
        where, what = hit[0].where(hit[1]), hit[0].evidence(hit[1])
    elif iap:
        where, what = repo.deps[iap[0]], f"in-app purchase library {iap[0]}"
    else:
        return []
    # Native paywalls in Dart/Swift/Kotlin carry the renewal text too.
    copy_files = repo.user_files() + [f for f in repo.code_files() if f.ext in (".dart", ".swift", ".kt")]
    if repo.first(RENEWAL_TERMS, copy_files):
        return []
    return [rule.hit(
        repo, where, f"subscription: {what}; no renewal terms in user-facing text",
        "The FTC's negative-option rules and state auto-renewal laws (e.g. California) require price, interval and "
        "how to cancel before purchase, and app reviewers reject paywalls without them.",
        "Next to the subscribe button, state the price, the interval, that it renews automatically, and how to "
        "cancel (e.g. '$9/month, renews monthly until you cancel in Settings').",
    )]


UGC_NAMES = "comments|posts|reviews|messages|uploads|threads|replies"
UGC_TABLE = re.compile(rf"create\s+table\s+(?:if\s+not\s+exists\s+)?(?:\"?public\"?\.)?\"?({UGC_NAMES})\"?(?![\w])", re.I)
UGC_CLIENT = re.compile(rf"\.from\(\s*[\"'`]({UGC_NAMES})[\"'`]|\bcollection\(\s*(?:\w+\s*,\s*)?[\"'`]({UGC_NAMES})[\"'`]")
UGC_PRISMA = re.compile(r"^model\s+(Comment|Post|Review|Message|Upload|Thread|Reply)\s*\{", re.M)
UGC_ROUTE = re.compile(rf"(?:^|/)(?:src/)?(?:app|pages)/api/({UGC_NAMES})(?:/|\.|$)")
REPORT_PATH = re.compile(
    r"\breport\s*\(|\breport(?:Post|Content|Comment|User|Message|Review|Abuse)\b|"
    r"(?:table|from\(\s*[\"'`])\s*(?:\"?public\"?\.)?[\"']?\w*reports\b|>\s*Report\b|[\"'`]Report(?: \w+)?[\"'`]|"
    r"\bflag(?:Post|Content|Comment)\b|content_reports|abuse_reports"
)


def l14_ugc_without_report(repo: Repo, rule: Rule) -> list[Finding]:
    # In an app with an AI SDK, "messages" is the chat history with the model, not content other users see.
    skip = {"messages"} if ai_deps(repo) else set()
    hit = None
    for f in repo.sql_files() + repo.code_files() + [f for f in repo.files if f.ext == ".prisma"]:
        for pattern in (UGC_TABLE, UGC_CLIENT, UGC_PRISMA):
            for m in pattern.finditer(f.code):
                name = next(g for g in m.groups() if g).lower()
                if name not in skip and not (name == "message" and "messages" in skip):
                    hit = (f.where(f.line_at(m.start())), f.evidence(f.line_at(m.start())))
                    break
            if hit:
                break
        if hit:
            break
    if not hit:
        route = next((p for p in repo.paths if UGC_ROUTE.search(p) and UGC_ROUTE.search(p).group(1) not in skip), None)
        if route:
            hit = (f"{route}:1", f"user-content route {route}")
    if not hit or repo.first(REPORT_PATH, repo.source_files() + repo.sql_files()):
        return []
    return [rule.hit(
        repo, hit[0], f"user-generated content: {hit[1]}; no report action found",
        "The EU DSA requires a way to report illegal content, and App Store 1.2 and Google Play's UGC policy reject "
        "apps whose user posts can't be reported.",
        "Add a 'Report' action on each post or comment that writes to a `reports` table, and review reports on a "
        "stated schedule; apps also need a way to block users.",
    )]


# --- D: design, copy and SEO ---------------------------------------------------

def per_file_offsets(rule: Rule, repo: Repo, files: Iterable[SourceFile], find: Callable[[SourceFile], list[int]],
                     why: str, fix: str) -> list[Finding]:
    """Like per_file, for checks that aren't a single regex."""
    out = []
    for f in files:
        offsets = sorted(find(f))
        if offsets:
            n = f.line_at(offsets[0])
            more = f" ({len(offsets)} in this file)" if len(offsets) > 1 else ""
            out.append(rule.hit(repo, f.where(n), f.evidence(n) + more, why, fix))
    return out


def repo_total(rule: Rule, repo: Repo, counts: Counter, first: tuple[SourceFile, int] | None, what: str,
               why: str, fix: str) -> list[Finding]:
    """One repo-level finding: the total, the top files, and the first location."""
    total = sum(counts.values())
    where = first[0].where(first[1]) if first else next(iter(counts))
    return [rule.hit(repo, where, f"{total} {what} in {len(counts)} files: {top_files(counts)}", why, fix)]


def strings_with(f: SourceFile, *patterns: re.Pattern) -> list[int]:
    """Offsets of quoted strings (class strings, in practice) that match every pattern."""
    return [s.start() for s in STRING_AT.finditer(f.code) if all(p.search(s.group(0)) for p in patterns)]


GRADIENT_CLASS = re.compile(r"\bbg-(?:gradient|linear)-to-")
PURPLE_STOP = re.compile(r"\b(?:from|via|to)-(?:purple|violet|indigo|fuchsia)-\d+")
PURPLE_CSS_GRADIENT = re.compile(r"linear-gradient\([^)]*#(?:8b5cf6|7c3aed|6366f1|a855f7|6d28d9|4f46e5|9333ea)\b", re.I)


def d01_purple_gradient(repo: Repo, rule: Rule) -> list[Finding]:
    def find(f: SourceFile) -> list[int]:
        return strings_with(f, GRADIENT_CLASS, PURPLE_STOP) + [m.start() for m in PURPLE_CSS_GRADIENT.finditer(f.code)]

    return per_file_offsets(
        rule, repo, repo.design_files(), find,
        "The purple-to-blue gradient is the default look of AI-generated landing pages, so visitors read the site as "
        "a template.",
        "Use the brand's own colors: one solid accent, or a gradient built from the brand palette.",
    )


BG_CLIP_TEXT = re.compile(r"\bbg-clip-text\b")
TEXT_TRANSPARENT = re.compile(r"\btext-transparent\b")
CSS_CLIP_TEXT = re.compile(r"background-clip\s*:\s*text", re.I)


def d02_gradient_text(repo: Repo, rule: Rule) -> list[Finding]:
    def find(f: SourceFile) -> list[int]:
        return strings_with(f, BG_CLIP_TEXT, TEXT_TRANSPARENT) + [m.start() for m in CSS_CLIP_TEXT.finditer(f.code)]

    return per_file_offsets(
        rule, repo, repo.design_files(), find,
        "Gradient headline text is one of the most recognizable AI-template tells and often fails contrast checks.",
        "Set headlines in a solid text color and let type size and weight carry the emphasis.",
    )


BACKDROP_BLUR = re.compile(r"\bbackdrop-blur\b|(?<!-webkit-)backdrop-filter\s*:\s*blur", re.I)


def d03_glassmorphism(repo: Repo, rule: Rule) -> list[Finding]:
    counts = repo.count(BACKDROP_BLUR, repo.design_files())
    if sum(counts.values()) < 3:
        return []
    return repo_total(
        rule, repo, counts, repo.first(BACKDROP_BLUR, repo.design_files()), "backdrop-blur uses",
        "Frosted-glass panels everywhere are a stock AI-template look and cost scrolling performance on phones.",
        "Keep blur for one overlay at most; give cards a solid surface color and a clear border.",
    )


BORDER_LEFT = re.compile(r"\bborder-l-(?:2|4|8)\b")
BORDER_COLOR = re.compile(
    r"\bborder-(?:l-)?(?:red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|"
    r"pink|rose|slate|gray|zinc|neutral|stone)-\d{2,3}\b"
)


def d04_left_border_cards(repo: Repo, rule: Rule) -> list[Finding]:
    counts: Counter = Counter()
    first = None
    for f in repo.design_files():
        offsets = strings_with(f, BORDER_LEFT, BORDER_COLOR)
        if offsets:
            counts[f.rel] += len(offsets)
            first = first or (f, f.line_at(offsets[0]))
    if sum(counts.values()) < 2:
        return []
    return repo_total(
        rule, repo, counts, first, "colored left-border cards",
        "A thick colored left border on every card is a signature of AI-generated dashboards and feature grids.",
        "Drop the accent border, or use it for one meaning only (e.g. alerts) with a consistent color.",
    )


LUCIDE_IMPORT = re.compile(r"import\s*\{([^}]*)\}\s*from\s*[\"'](?:lucide-react|lucide-vue-next|lucide-svelte|@lucide/[\w-]+)[\"']", re.S)
LUCIDE_DEFAULT = re.compile(r"import\s+(\w+)\s+from\s*[\"'](?:lucide-svelte|@lucide/svelte|lucide-react)/icons/[\w-]+[\"']")


def d05_many_icons(repo: Repo, rule: Rule) -> list[Finding]:
    icons: set[str] = set()
    per_file_icons: Counter = Counter()
    first = None
    for f in repo.code_files():
        names = set()
        for m in LUCIDE_IMPORT.finditer(f.code):
            for part in m.group(1).split(","):
                part = re.sub(r"^\s*type\s+", "", part).strip()
                if part:
                    names.add(part.split(" as ")[0].strip())
        names.update(m.group(1) for m in LUCIDE_DEFAULT.finditer(f.code))
        if names:
            icons |= names
            per_file_icons[f.rel] = len(names)
            first = first or (f, f.line_at((LUCIDE_IMPORT.search(f.code) or LUCIDE_DEFAULT.search(f.code)).start()))
    if len(icons) < 20:
        return []
    return [rule.hit(
        repo, first[0].where(first[1]) if first else ".",
        f"{len(icons)} distinct lucide icons across {len(per_file_icons)} files: {top_files(per_file_icons)}",
        "An icon beside every heading and bullet is how AI-generated pages fill space, and it dilutes the icons that "
        "carry meaning.",
        "Keep icons where they help recognition (navigation, actions) and remove decorative ones next to headings "
        "and list items.",
    )]


INTER_FONT = re.compile(
    r"import\s*\{[^}]*\bInter\b[^}]*\}\s*from\s*[\"']next/font/google[\"']|@fontsource(?:-variable)?/inter\b|"
    r"font-family\s*:\s*[^;\n]*\bInter\b|fontFamily\s*:[^;]{0,120}?[\"']Inter\b|family=Inter(?![+\w])|"
    r"--font-[\w-]+\s*:\s*[^;\n]*\bInter\b"
)


def d06_inter_font(repo: Repo, rule: Rule) -> list[Finding]:
    hit = repo.first(INTER_FONT, repo.source_files())
    if not hit:
        return []
    f, n = hit
    return [rule.hit(
        repo, f.where(n), f.evidence(n),
        "Inter is the default of countless AI-generated and template sites, so it reads as 'generated' before anyone "
        "reads a word.",
        "Pick a typeface that fits the brand (e.g. Geist, IBM Plex Sans, Instrument Sans or Source Serif via "
        "next/font) and set it in one place.",
    )]


# U+2600-27BF counts only where Unicode gives the character emoji presentation, or when U+FE0F
# asks for it: ✓ ✕ ★ ☰ ♠ are text symbols, ✅ ✨ ❌ ⚡ are emoji.
EMOJI_PRESENTATION_BMP = (
    "\u2614\u2615\u2648-\u2653\u267F\u2693\u26A1\u26AA\u26AB\u26BD\u26BE\u26C4\u26C5\u26CE\u26D4\u26EA"
    "\u26F2\u26F3\u26F5\u26FA\u26FD\u2705\u270A\u270B\u2728\u274C\u274E\u2753-\u2755\u2757\u2795-\u2797\u27B0\u27BF"
)
EMOJI = re.compile(
    "[\U0001F300-\U0001FAFF\U0001F000-\U0001F2FF\u2B50\u2B55\u231A-\u231B\u23E9-\u23FA" + EMOJI_PRESENTATION_BMP + "]"
    "|[\u2600-\u27BF]\uFE0F"
)


def d07_emoji(repo: Repo, rule: Rule) -> list[Finding]:
    counts = repo.count(EMOJI, repo.user_files())
    if sum(counts.values()) < 3:
        return []
    return repo_total(
        rule, repo, counts, repo.first(EMOJI, repo.user_files()), "emoji",
        "Emoji as bullets and headings are a strong tell of AI-written copy and render differently on every device.",
        "Replace them with the icon set you already use or with plain words; keep emoji only where the brand voice "
        "really uses them.",
    )


SCROLL_REVEAL = re.compile(r"\bwhileInView\b|data-aos=|AOS\.init|animate-fade-in|fadeInUp|\buseInView\b|ScrollReveal")


def d08_scroll_reveal(repo: Repo, rule: Rule) -> list[Finding]:
    files = [f for f in repo.files if f.user_facing or f.is_style or f.is_code]
    counts = repo.count(SCROLL_REVEAL, files)
    if sum(counts.values()) < 5:
        return []
    return repo_total(
        rule, repo, counts, repo.first(SCROLL_REVEAL, files), "scroll-reveal animations",
        "Every section fading in on scroll is a stock AI-template effect; it delays content and bothers users who "
        "prefer reduced motion.",
        "Show content immediately; keep at most one purposeful animation and respect prefers-reduced-motion.",
    )


TEXTURE = re.compile(
    r"\bbg-grid\b|\bbg-grid-|\bbg-dots?\b|grid-?pattern|dot-?pattern|\bbg-noise\b|noise\.(?:png|svg|webp)|"
    r"feTurbulence|\bbg-grain\b|grain-(?:overlay|texture|bg)|film-grain|grain\.(?:png|svg|webp)|"
    r"class(?:Name)?\s*=\s*[\"'][^\"']*\bgrain\b",
    re.I,
)


def d09_filler_texture(repo: Repo, rule: Rule) -> list[Finding]:
    files = [f for f in repo.files if f.user_facing or f.is_style or f.ext == ".svg"]
    hit = repo.first(TEXTURE, files)
    asset = next((p for p in repo.paths if re.search(r"(?:^|/)(?:noise|grain)\.(?:png|svg|webp)$", p, re.I)), None)
    if not hit and not asset:
        return []
    where, what = (hit[0].where(hit[1]), hit[0].evidence(hit[1])) if hit else (asset, f"texture asset {asset}")
    return [rule.hit(
        repo, where, what,
        "Grid, dot and noise backgrounds are filler texture from AI templates and add visual noise without meaning.",
        "Remove the texture layer and use whitespace and a plain background.",
    )]


CURSOR_EFFECT = re.compile(
    r"cursor\s*:\s*none|\bcursor-none\b|cursor-?glow|custom-?cursor|mouse-?follow|cursor-?follow|<Spotlight\b|"
    r"spotlight-(?:effect|card|glow|cursor)",
    re.I,
)


def d10_cursor_effect(repo: Repo, rule: Rule) -> list[Finding]:
    hit = repo.first(CURSOR_EFFECT, repo.design_files())
    if not hit:
        return []
    f, n = hit
    return [rule.hit(
        repo, f.where(n), f.evidence(n),
        "Custom cursors and spotlight effects are an AI-template flourish that hides the real pointer and gets in the "
        "way on touch and keyboard.",
        "Remove the effect and keep the system cursor.",
    )]


EM_DASH = re.compile("\u2014|&mdash;")


def d11_em_dashes(repo: Repo, rule: Rule) -> list[Finding]:
    counts = repo.count(EM_DASH, repo.user_files())
    if sum(counts.values()) < 5:
        return []
    return repo_total(
        rule, repo, counts, repo.first(EM_DASH, repo.user_files()), "em dashes",
        "Heavy em-dash use is one of the best-known tells of AI-written copy, and readers now notice it.",
        "Rewrite those sentences with periods, commas or parentheses; keep an em dash only where a person would.",
    )


BUZZWORDS = re.compile(
    r"\b(?:seamless|seamlessly|elevate|unleash|empower|revolutionize|revolutionary|cutting-edge|game-changer|"
    r"game-changing|next-level|supercharge|effortless|effortlessly|delve|leverage|robust|innovative|harness|"
    r"streamline|world-class|best-in-class|state-of-the-art|all-in-one|reimagine|reimagined|unparalleled|"
    r"unlock your potential|in today['\u2019]s fast-paced|look no further|to the next level|whether you['\u2019]re)\b",
    re.I,
)


def d12_buzzwords(repo: Repo, rule: Rule) -> list[Finding]:
    words: Counter = Counter()
    first = None
    for f in repo.user_files():
        for m in BUZZWORDS.finditer(f.copy):
            words[m.group(0).lower().replace("\u2019", "'")] += 1
            first = first or (f, f.line_at(m.start()))
    if sum(words.values()) < 3 or not first:
        return []
    listed = ", ".join(f"{w} ×{c}" for w, c in words.most_common(8))
    return [rule.hit(
        repo, first[0].where(first[1]), f"{sum(words.values())} buzzwords: {listed}",
        "Words like 'seamless' and 'elevate' are what visitors now recognize as AI-written copy, and they say "
        "nothing specific about the product.",
        "Replace each with the concrete thing the product does, with a number or example where possible.",
    )]


PLACEHOLDER_COPY = re.compile(
    r"(?i:lorem ipsum)|\b(?:John|Jane) (?:Doe|Smith)\b|\bAcme\b|\bYour Company\b|\bCompany Name\b|\bYour Name\b|"
    r"yourdomain\.com|via\.placeholder\.com|placehold\.co|\bplaceholder\.com|picsum\.photos|i\.pravatar\.cc|"
    r"randomuser\.me|(?i:coming soon)"
)
def _real_placeholder(f: SourceFile, m: re.Match) -> bool:
    """'Company Name' and 'Your Name' count only inside sentence copy, e.g. '© 2026 Your Company Name.'

    A text node that is just the phrase (a form label, a table header) or a quoted string (a field
    map) is a real label.
    """
    if m.group(0) not in ("Company Name", "Your Name"):
        return True
    text = f.copy
    left, right = text.rfind(">", 0, m.start()), text.find("<", m.end())
    if left < 0 or right < 0 or re.search(r"[<{}\"'`]", text[left + 1:m.start()] + text[m.end():right]):
        return False
    rest = (text[left + 1:m.start()] + text[m.end():right]).strip(" \t\n*:()")
    return bool(rest)


def d13_placeholder_content(repo: Repo, rule: Rule) -> list[Finding]:
    return per_file(
        rule, repo, repo.user_files(), PLACEHOLDER_COPY,
        "Visitors who see template names, stock avatars or 'coming soon' conclude the product is unfinished or fake.",
        "Never invent the replacement: ask the owner for the real name, photo, number or date, or delete the section.",
        attr="copy", keep=_real_placeholder,
    )


SOCIAL_PROOF = re.compile(
    r"(?i:trusted by \d)|\d[\d,.]*[kKmM]?\+\s*(?i:users|customers|teams|developers|companies|businesses|creators)\b|"
    r"\d(?:\.\d)?/5\s*(?i:stars|rating)|(?i:\brated \d)|(?<![\w&])#1\s"
)


def d14_social_proof(repo: Repo, rule: Rule) -> list[Finding]:
    return per_file(
        rule, repo, repo.user_files(), SOCIAL_PROOF,
        "The FTC's 2024 rule bans fake reviews and testimonials and made-up usage numbers, with civil penalties per "
        "violation.",
        "The owner confirms each number or rating is true and has a source; remove any that isn't.",
        attr="copy",
    )


DEFAULT_TITLE = re.compile(
    r"<title>\s*(?:Vite \+ React(?: \+ TS)?|Vite App|React App|Create Next App|Nuxt|SvelteKit|Astro)\s*</title>"
    r"|title\s*:\s*[\"']Create Next App[\"']|description\s*:\s*[\"']Generated by create next app[\"']",
    re.I,
)
DEFAULT_ASSETS = ("public/vite.svg", "public/next.svg", "public/vercel.svg", "src/assets/react.svg")
ICON_LINK = re.compile(r"<link[^>]*rel\s*=\s*[\"'](?:shortcut )?icon[\"'][^>]*>", re.I)


def d15_scaffold_metadata(repo: Repo, rule: Rule) -> list[Finding]:
    why_meta = "Search results and link previews show the scaffold's name instead of your product's."
    out = []
    for f in repo.source_files():
        for m in DEFAULT_TITLE.finditer(f.code):
            n = f.line_at(m.start())
            out.append(rule.hit(repo, f.where(n), f.evidence(n), why_meta,
                                "Set a real title and description in the root metadata (`export const metadata = "
                                "{ title, description }` or the <title> in index.html)."))
    for asset in DEFAULT_ASSETS:
        icon_name = asset.rsplit("/", 1)[-1]
        linked = None
        for f in repo.source_files():
            for m in ICON_LINK.finditer(f.code):
                if icon_name in m.group(0):
                    linked = (f, f.line_at(m.start()))
                    break
            if linked:
                break
        if linked:
            out.append(rule.hit(repo, linked[0].where(linked[1]), f"favicon is the scaffold's {icon_name}",
                                "The browser tab shows the framework's logo instead of yours.",
                                "Replace it with your own icon (app/icon.png or public/favicon.ico) and update the link."))
        elif asset in repo.path_set:
            out.append(rule.hit(repo, asset, f"default scaffold asset {asset} still present",
                                "Leftover scaffold assets signal an unfinished template to anyone who looks.",
                                f"Delete {asset} and any reference to it."))
    return out


def _basics_present(repo: Repo) -> dict[str, bool]:
    names = [p.rsplit("/", 1)[-1].lower() for p in repo.paths if not TEST_NAME.search(p)]

    def named(pattern: str) -> bool:
        return any(re.fullmatch(pattern, n) for n in names)

    def mentions(pattern: str) -> bool:
        return repo.first(re.compile(pattern), repo.source_files()) is not None

    return {
        "robots": named(r"robots\.(?:txt|ts|js|tsx|jsx)") or repo.has_dep("@nuxtjs/robots", "astro-robots-txt")
        or mentions(r"generateRobotsTxt\s*:\s*true"),
        "sitemap": named(r"sitemap[\w.\-]*\.(?:xml|ts|js|tsx|jsx)")
        or repo.has_dep("next-sitemap", "@astrojs/sitemap", "@nuxtjs/sitemap", "sitemap"),
        "404 page": named(r"404(?:\.[\w]+)+|not-found\.[\w]+|\+error\.svelte|error\.vue"),
        "OG image": named(r"(?:opengraph|twitter)-image\.[\w]+") or mentions(r"og:image|\bopenGraph\b"),
        "favicon": named(r"favicon\.[\w]+|icon\.(?:png|svg|ico|tsx|jsx|ts|js)|apple-icon\.[\w]+|apple-touch-icon[\w\-]*\.png")
        or mentions(r"rel\s*=\s*[\"'](?:shortcut )?icon[\"']|\bicons\s*:\s*[\[{]"),
    }


BASICS = {
    # key: (Next.js app-router file, static file, why, fix)
    "robots": ("robots.ts", "public/robots.txt",
               "Crawlers get no rules or sitemap pointer and may index staging paths.",
               "Add app/robots.ts (Next.js) or public/robots.txt with `User-agent: *`, `Allow: /` and a Sitemap line."),
    "sitemap": ("sitemap.ts", "public/sitemap.xml", "Search engines discover new pages slowly without a sitemap.",
                "Add app/sitemap.ts (Next.js), next-sitemap or @astrojs/sitemap, or a public/sitemap.xml."),
    "404 page": ("not-found.tsx", "public/404.html",
                 "Broken links land on the framework's default error page, which looks abandoned.",
                 "Add a custom not-found page (app/not-found.tsx, pages/404.tsx, src/routes/+error.svelte) with a link home."),
    "OG image": ("opengraph-image.png", "public/og-image.png", "Shared links show a blank card on social networks and chat apps.",
                 "Add app/opengraph-image.png (Next.js) or an og:image meta tag with a 1200x630 image."),
    "favicon": ("icon.png", "public/favicon.ico", "The browser tab and bookmarks show a blank or default icon.",
                "Add app/icon.png or public/favicon.ico and a <link rel=\"icon\">."),
}


def d16_seo_basics(repo: Repo, rule: Rule) -> list[Finding]:
    if not repo.has_web:
        return []
    root = repo.web_root
    app_dir = next((root + d for d in ("src/app", "app") if any(p.startswith(root + d + "/") for p in repo.paths)), None)
    out = []
    for key, present in _basics_present(repo).items():
        if present:
            continue
        next_file, static_file, why, fix = BASICS[key]
        hint = f"{app_dir}/{next_file}" if app_dir and repo.has_dep("next") else root + static_file
        out.append(rule.hit(repo, f"{hint} (missing)", f"no {key} found in the repo", why, fix))
    return out


H1_TAG = re.compile(r"<h1\b", re.I)


# A return, or an arrow that returns JSX; event-handler arrows (onClick={() => go()}) are not branches.
RENDER_BRANCH = re.compile(r"\breturn\b|=>\s*[(<]")


def d17_multiple_h1(repo: Repo, rule: Rule) -> list[Finding]:
    out = []
    for f in repo.user_files():
        hits = list(H1_TAG.finditer(f.code))
        # Loading, error and success states each return their own <h1>; only one renders at a time.
        # Count per return/arrow branch, not per file.
        cuts = [m.start() for m in RENDER_BRANCH.finditer(f.code)] if f.ext in JS_EXTS else []
        branch = Counter(bisect.bisect_right(cuts, h.start()) for h in hits)
        if hits and max(branch.values()) >= 2:
            n = f.line_at(hits[1].start())
            out.append(rule.hit(
                repo, f.where(n), f"{len(hits)} <h1> tags; second: {f.evidence(n)}",
                "Several top-level headings blur what the page is about for search engines and screen-reader users.",
                "Keep one <h1> per page and make the others <h2>.",
            ))
    return out


AI_BOTS = ("GPTBot", "ClaudeBot", "anthropic-ai", "CCBot", "Google-Extended", "PerplexityBot", "Applebot-Extended")


def _robots_blocked_bots(f: SourceFile) -> list[tuple[int, str]]:
    blocked, agents, in_rules = [], [], False
    for i, raw in enumerate(f.lines, 1):
        line = raw.split("#", 1)[0].strip()
        m = re.match(r"(?i)user-agent\s*:\s*(\S+)", line)
        if m:
            if in_rules:
                agents, in_rules = [], False
            agents.append((i, m.group(1)))
            continue
        if re.match(r"(?i)(?:dis)?allow\s*:", line):
            in_rules = True
            if re.fullmatch(r"(?i)disallow\s*:\s*/", line):
                blocked += [(n, a) for n, a in agents if any(a.lower() == b.lower() for b in AI_BOTS)]
    return blocked


def d18_ai_crawlers_blocked(repo: Repo, rule: Rule) -> list[Finding]:
    blocked: list[tuple[SourceFile, int, str]] = []
    for f in repo.files:
        if f.name == "robots.txt":
            blocked += [(f, n, a) for n, a in _robots_blocked_bots(f)]
        elif re.fullmatch(r"robots\.(?:ts|js|tsx|jsx)", f.name):
            for m in re.finditer(r"userAgent\s*:\s*([^\n]*)", f.code):
                window = f.code[m.start():m.start() + 300]
                bots = [b for b in AI_BOTS if b in m.group(1)]
                if bots and re.search(r"disallow\s*:\s*[\"']/[\"']", window):
                    blocked += [(f, f.line_at(m.start()), b) for b in bots]
    if not blocked:
        return []
    f, n, _ = blocked[0]
    bots = sorted({b for _f, _n, b in blocked})
    return [rule.hit(
        repo, f.where(n), f"Disallow: / for {', '.join(bots)}",
        "AI assistants that honor robots.txt can't read or cite the site, so it won't appear in their answers.",
        "Confirm this is intentional; if not, remove those groups or allow the public pages.",
    )]


STOCK_PRIMARY = re.compile(
    r"--primary\s*:\s*(?:222\.2\s+47\.4%\s+11\.2%|240\s+5\.9%\s+10%|0\s+0%\s+9%|"
    r"oklch\(\s*0\.205\s+0\s+0\s*\)|oklch\(\s*0\.21\s+0\.006\s+285\.885\s*\))\s*;"
)


def d19_stock_shadcn_theme(repo: Repo, rule: Rule) -> list[Finding]:
    if not any(p.rsplit("/", 1)[-1] == "components.json" for p in repo.paths):
        return []
    hit = repo.first(STOCK_PRIMARY, [f for f in repo.files if f.is_style])
    if not hit:
        return []
    f, n = hit
    return [rule.hit(
        repo, f.where(n), f.evidence(n),
        "The untouched shadcn/ui theme is instantly recognizable, so the product looks like every other generated app.",
        "Set --primary (and radius, fonts) to the brand's values in the theme CSS; `npx shadcn init` offers "
        "other base colors.",
    )]


# --- M: mobile app stores ----------------------------------------------------

def _capacitor_configs(repo: Repo) -> list[SourceFile]:
    return [f for f in repo.files if re.fullmatch(r"capacitor\.config\.(?:ts|js|mjs|cjs|json)", f.name)]


def _server_url(f: SourceFile) -> tuple[str, int] | None:
    if f.ext == ".json":
        try:
            url = (json.loads(f.text).get("server") or {}).get("url")
        except (ValueError, AttributeError):
            return None
        if isinstance(url, str) and url:
            idx = f.text.find('"url"')
            return url, f.line_at(idx) if idx >= 0 else 1
        return None
    m = re.search(r"\bserver\s*:\s*\{", f.code)
    if not m:
        return None
    block_end = matching_brace(f.code, m.end() - 1)
    u = re.search(r"\burl\s*:\s*[\"'`]([^\"'`]+)[\"'`]", f.code[m.end():block_end])
    return (u.group(1), f.line_at(m.end() + u.start())) if u else None


def _is_local_url(url: str) -> bool:
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = (parsed.hostname or "").lower()
    return (parsed.scheme == "http" or host in ("localhost", "0.0.0.0", "::1") or host.endswith(".local")
            or re.match(r"^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)", host) is not None)


def m01_capacitor_server_url(repo: Repo, rule: Rule) -> list[Finding]:
    out = []
    for f in _capacitor_configs(repo):
        found = _server_url(f)
        if not found:
            continue
        url, n = found
        if _is_local_url(url):
            why = ("Live-reload config left in: the release build tries to load a dev server that doesn't exist on "
                   "users' phones and opens to a blank screen.")
            fix = "Delete the server block before `npx cap sync`, or add it only when a live-reload env var is set."
        else:
            why = ("The app is a webview wrapper around a live website, which App Store guideline 4.2 rejects and "
                   "which breaks offline.")
            fix = "Remove server.url so Capacitor serves the bundled webDir, and add real native features."
        out.append(rule.hit(repo, f.where(n), f"server.url = {url}", why, fix))
    return out


BASE_CAPACITOR = frozenset(("@capacitor/core", "@capacitor/cli", "@capacitor/app", "@capacitor/status-bar",
                            "@capacitor/splash-screen", "@capacitor/keyboard", "@capacitor/ios", "@capacitor/android",
                            "@capacitor/assets"))
BASE_CORDOVA = frozenset(("cordova-plugin-whitelist", "cordova-plugin-splashscreen", "cordova-plugin-statusbar",
                          "cordova-plugin-ionic-webview", "cordova-plugin-ionic-keyboard", "cordova-android", "cordova-ios"))
NATIVE_PLUGIN = re.compile(r"capacitor|^cordova-plugin-|^@awesome-cordova-plugins/|^@ionic-native/|^@capawesome")


def m02_thin_wrapper(repo: Repo, rule: Rule) -> list[Finding]:
    if not repo.native & {"capacitor", "cordova"}:
        return []
    plugins = {d for d in repo.deps if NATIVE_PLUGIN.search(d)} - BASE_CAPACITOR - BASE_CORDOVA
    for f in repo.files:
        if f.name == "config.xml":
            plugins |= set(re.findall(r"<plugin\s+name=[\"']([\w@/.\-]+)[\"']", f.text)) - BASE_CORDOVA
    if len(plugins) >= 2:
        return []
    where = next((repo.deps[d] for d in sorted(repo.deps) if d.startswith("@capacitor/")), None)
    where = where or next((f"{f.rel}:1" for f in _capacitor_configs(repo)), "package.json")
    listed = ", ".join(sorted(plugins)) or "none"
    return [rule.hit(
        repo, where, f"native plugins beyond the base set: {len(plugins)} ({listed})",
        "App Store guideline 4.2 (minimum functionality) and Play's webview policy reject apps that are a website in "
        "a shell.",
        "Add native value users can feel: push notifications, offline storage, camera, share sheet, widgets, or "
        "biometrics.",
    )]


def m03_no_in_app_deletion(repo: Repo, rule: Rule) -> list[Finding]:
    if has_account_deletion(repo):
        return []
    return [rule.hit(
        repo, repo.signup_where or ".", f"native app with signup at {repo.signup_where}; no account-deletion path found",
        "App Store guideline 5.1.1(v) rejects apps with signup but no in-app account deletion, and Google Play also "
        "requires a web link for deletion requests.",
        DELETION_FIX + " Link a web deletion page in the Play Console Data safety form.",
    )]


THIRD_PARTY_LOGIN = re.compile(
    r"provider\s*:\s*[\"'](?:google|facebook|github|discord|twitter|x|linkedin_oidc|azure)[\"']|"
    r"@react-native-google-signin|GoogleAuthProvider|GoogleSignIn"
)
APPLE_LOGIN = re.compile(
    r"provider\s*:\s*[\"']apple[\"']|expo-apple-authentication|@invertase/react-native-apple-authentication|"
    r"sign_in_with_apple|SignInWithApple|AppleAuthProvider|@capacitor-community/apple-sign-in"
)


def m04_no_sign_in_with_apple(repo: Repo, rule: Rule) -> list[Finding]:
    if not repo.has_ios:
        return []
    files = repo.source_files()
    hit = repo.first(THIRD_PARTY_LOGIN, files)
    if not hit or repo.first(APPLE_LOGIN, files) or repo.has_dep(
            "expo-apple-authentication", "@invertase/react-native-apple-authentication", "sign_in_with_apple",
            "@capacitor-community/apple-sign-in"):
        return []
    f, n = hit
    return [rule.hit(
        repo, f.where(n), f.evidence(n),
        "App Store guideline 4.8 requires an equivalent privacy-focused login next to third-party logins, which in "
        "practice means Sign in with Apple.",
        "Add Sign in with Apple (expo-apple-authentication or the Capacitor plugin, then "
        "`supabase.auth.signInWithIdToken({ provider: 'apple', token })`).",
    )]


WEB_CHECKOUT = re.compile(
    r"redirectToCheckout|checkout\.sessions\.create|buy\.stripe\.com|@stripe/stripe-react-native|lemonsqueezy|"
    r"@paddle/|paddle\.js|\bPaddle\.(?:Checkout|Setup|Initialize)\b",
    re.I,
)


def m05_web_checkout_no_iap(repo: Repo, rule: Rule) -> list[Finding]:
    if repo.has_dep(*IAP_DEPS):
        return []
    hit = repo.first(WEB_CHECKOUT, repo.source_files())
    if not hit:
        return []
    f, n = hit
    return [rule.hit(
        repo, f.where(n), f.evidence(n),
        "Apple and Google require their in-app purchase for digital goods sold inside the app; external payment links "
        "are allowed only in some regions and under specific rules.",
        "If you sell digital goods or subscriptions, add StoreKit/Play Billing via RevenueCat (react-native-purchases, "
        "@revenuecat/purchases-capacitor); physical goods and services can keep web checkout.",
    )]


RESTORE_PURCHASES = re.compile(
    r"restorePurchases|restoreTransactions|restoreCompletedTransactions|syncPurchases|restore purchases", re.I
)


def m06_no_restore_purchases(repo: Repo, rule: Rule) -> list[Finding]:
    iap = repo.deps_matching(IAP_DEPS)
    if not iap or repo.first(RESTORE_PURCHASES, repo.source_files()):
        return []
    return [rule.hit(
        repo, repo.deps[iap[0]], f"in-app purchase library {iap[0]}; no restore-purchases call or button found",
        "App Review rejects apps with purchases but no 'Restore Purchases' button (guideline 3.1.1), and users who "
        "reinstall lose what they paid for.",
        "Add a 'Restore Purchases' button that calls the library's restore method (e.g. Purchases.restorePurchases()).",
    )]


TARGET_SDK = re.compile(r"\btargetSdk(?:Version)?\b[\"']?\s*[=:(]?\s*[\"']?(\d{2})\b")


def m07_target_sdk(repo: Repo, rule: Rule) -> list[Finding]:
    candidates = []
    for f in repo.files:
        if re.search(r"(?:^|/)android/app/build\.gradle(?:\.kts)?$|(?:^|/)android/variables\.gradle$", f.rel):
            candidates.append(f)
        elif f.name == "app.json" or re.fullmatch(r"app\.config\.(?:js|ts|mjs|cjs)", f.name):
            candidates.append(f)
    out = []
    for f in candidates:
        m = TARGET_SDK.search(f.code)
        if not m:
            continue
        sdk, n = int(m.group(1)), f.line_at(m.start())
        if sdk < PLAY_TARGET_SDK_FLOOR:
            out.append(rule.hit(
                repo, f.where(n), f"targetSdk {sdk} (Play requires {PLAY_TARGET_SDK_FLOOR})",
                f"Google Play rejects new apps and updates that target below API {PLAY_TARGET_SDK_FLOOR}.",
                f"Raise targetSdkVersion to {PLAY_TARGET_SDK_FLOOR}, then test runtime permissions and edge-to-edge "
                "layout on a current Android emulator.",
            ))
        elif sdk == PLAY_TARGET_SDK_FLOOR:
            out.append(rule.hit(
                repo, f.where(n), f"targetSdk {sdk} equals the current Play floor",
                "The floor rises every August, so this build stops being accepted after the next deadline.",
                "Confirm the current requirement in Play Console and plan the next targetSdk bump before August.",
                severity="P2",
            ))
    return out


SENSITIVE_PERMISSIONS = (
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS", "READ_CONTACTS",
    "WRITE_CONTACTS", "ACCESS_BACKGROUND_LOCATION", "QUERY_ALL_PACKAGES", "MANAGE_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES",
    "READ_MEDIA_VIDEO", "REQUEST_INSTALL_PACKAGES", "SYSTEM_ALERT_WINDOW", "USE_EXACT_ALARM", "BIND_ACCESSIBILITY_SERVICE",
)


def _expo_config(f: SourceFile) -> dict:
    try:
        data = json.loads(f.text)
    except ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    return data.get("expo", data) if isinstance(data.get("expo", data), dict) else {}


def m08_sensitive_permission(repo: Repo, rule: Rule) -> list[Finding]:
    found: dict[str, tuple[SourceFile, int]] = {}
    for f in repo.files:
        if f.name == "AndroidManifest.xml":
            for m in re.finditer(r"<uses-permission[^>]*>", f.code):
                tag = m.group(0)
                p = re.search(r"android\.permission\.(\w+)", tag)
                if p and p.group(1) in SENSITIVE_PERMISSIONS and 'tools:node="remove"' not in tag:
                    found.setdefault(p.group(1), (f, f.line_at(m.start())))
        elif f.name == "app.json":
            perms = (_expo_config(f).get("android") or {}).get("permissions") or []
            for perm in perms if isinstance(perms, list) else []:
                name = str(perm).rsplit(".", 1)[-1]
                if name in SENSITIVE_PERMISSIONS:
                    idx = f.text.find(str(perm))
                    found.setdefault(name, (f, f.line_at(idx) if idx >= 0 else 1))
        elif re.fullmatch(r"app\.config\.(?:js|ts|mjs|cjs)", f.name):
            block = re.search(r"\bpermissions\s*:\s*\[([^\]]*)\]", f.code)
            for name in SENSITIVE_PERMISSIONS:
                if block and re.search(rf"\b{name}\b", block.group(1)):
                    found.setdefault(name, (f, f.line_at(block.start())))
    return [
        rule.hit(
            repo, f.where(n), f"android permission {name}",
            f"Google Play restricts {name}: without an approved declaration in Play Console the release is rejected "
            "or removed.",
            f"Remove {name} if a narrower API works (photo picker, exact-alarm alternatives), or declare and justify "
            "it in Play Console.",
        )
        for name, (f, n) in found.items()
    ]


def _expo_ios_config(repo: Repo) -> list[tuple[SourceFile, str]]:
    """(file, text) for Expo app configs, for key lookups."""
    return [(f, f.text) for f in repo.files
            if (f.name == "app.json" and '"expo"' in f.text) or re.fullmatch(r"app\.config\.(?:js|ts|mjs|cjs)", f.name)]


def m09_privacy_manifest(repo: Repo, rule: Rule) -> list[Finding]:
    ios_dirs = sorted({re.match(r"(.*?(?:^|/)ios)/", p).group(1) for p in repo.paths
                       if re.search(r"(?:^|/)ios/(?:.*/)?[^/]+\.xcodeproj/", p)})
    out = []
    for d in ios_dirs:
        if not any(p.startswith(d + "/") and p.endswith("PrivacyInfo.xcprivacy") for p in repo.paths):
            out.append(rule.hit(
                repo, f"{d}/ (no PrivacyInfo.xcprivacy)", f"{d}/ has an Xcode project but no PrivacyInfo.xcprivacy",
                "App Store Connect rejects uploads that use required-reason APIs (UserDefaults, file timestamps) "
                "without a privacy manifest.",
                "Add PrivacyInfo.xcprivacy to the app target in Xcode (File > New > App Privacy) and declare the APIs "
                "and data types you use.",
            ))
    if not ios_dirs and "expo" in repo.native and repo.has_ios:
        configs = _expo_ios_config(repo)
        if configs and not any("privacyManifests" in text for _f, text in configs):
            f = configs[0][0]
            out.append(rule.hit(
                repo, f"{f.rel}:1", f"{f.rel} has no ios.privacyManifests",
                "Expo adds privacy manifests for its own modules, but APIs your code and other libraries use still "
                "need declaring or the upload is rejected.",
                "Add `ios.privacyManifests` (NSPrivacyAccessedAPITypes with reasons) to the Expo config.",
                severity="P2",
            ))
    return out


USAGE_PLIST = re.compile(r"<key>\s*(NS\w+UsageDescription)\s*</key>\s*(?:<string>([^<]*)</string>|<string\s*/>)")
USAGE_JS = re.compile(r"[\"']?(NS\w+UsageDescription)[\"']?\s*:\s*[\"'`]([^\"'`]*)[\"'`]")
GENERIC_USAGE = re.compile(r"needs access|requires access|would like to access|permission", re.I)
EXPO_DEFAULT_USAGE = re.compile(r"^Allow \$\(PRODUCT_NAME\) to (?:access|use) (?:your )?[\w ]+\.?$")


def _weak_usage(text: str) -> str | None:
    text = text.strip()
    if not text:
        return "empty"
    if len(text) < 25:
        return "under 25 characters"
    if GENERIC_USAGE.search(text) or EXPO_DEFAULT_USAGE.match(text):
        return "generic"
    return None


def m10_usage_descriptions(repo: Repo, rule: Rule) -> list[Finding]:
    out = []
    for f in repo.files:
        if f.name == "Info.plist":
            pattern = USAGE_PLIST
        elif f.name == "app.json" or re.fullmatch(r"app\.config\.(?:js|ts|mjs|cjs)", f.name):
            pattern = USAGE_JS
        else:
            continue
        for m in pattern.finditer(f.code):
            value = m.group(2) or ""
            problem = _weak_usage(value)
            if problem:
                n = f.line_at(m.start())
                out.append(rule.hit(
                    repo, f.where(n), f"{m.group(1)} is {problem}: \"{value.strip()}\"",
                    "App Review rejects permission prompts that don't say specifically what the app does with the "
                    "access (guideline 5.1.1).",
                    f"Write {m.group(1)} as the concrete reason, e.g. 'Scan receipts so the amount fills in "
                    "automatically.'",
                ))
    return out


IPAD_SUPPORT = re.compile(
    r"supportsTablet[\"']?\s*:\s*true|TARGETED_DEVICE_FAMILY\s*=\s*\"?1,2\"?|"
    r"<key>UIDeviceFamily</key>\s*<array>(?:(?!</array>).)*<integer>2</integer>",
    re.S,
)


def m11_ipad_supported(repo: Repo, rule: Rule) -> list[Finding]:
    files = [f for f in repo.files if f.name in ("app.json", "Info.plist", "project.pbxproj")
             or re.fullmatch(r"app\.config\.(?:js|ts|mjs|cjs)", f.name)]
    hit = repo.first(IPAD_SUPPORT, files)
    if not hit:
        return []
    f, n = hit
    return [rule.hit(
        repo, f.where(n), f.evidence(n),
        "Reviewers test the iPad layout of any app that supports iPad, and a stretched phone layout gets rejected.",
        "Check every screen on an iPad simulator, or turn iPad support off (supportsTablet: false / "
        "TARGETED_DEVICE_FAMILY = 1) if you don't design for it.",
    )]


# --- Registry ----------------------------------------------------------------

RULES = [
    Rule("S01", "P0", "secrets", "AGENT", "Secret-looking name behind a public env prefix", s01_public_env_secret),
    Rule("S02", "P0", "secrets", "HUMAN", "Hardcoded secret in a source file", s02_hardcoded_secret),
    Rule("S03", "P0", "secrets", "HUMAN", ".env file tracked by git", s03_env_tracked, ("git",)),
    Rule("S04", "P0", "secrets", "HUMAN", "Secret in git history", s04_history_secret, ("git",)),
    Rule("S05", "P1", "secrets", "AGENT", ".env not covered by .gitignore", s05_env_not_ignored),
    Rule("S06", "P0", "secrets", "AGENT", "Supabase service-role key in client code", s06_service_role_in_client),
    Rule("S07", "P0", "secrets", "AGENT", "AI SDK running in the browser", s07_browser_ai_key),
    Rule("S08", "P0", "data", "AGENT", "Public table without row level security", s08_table_without_rls),
    Rule("S09", "P1", "data", "AGENT", "RLS policy that allows everything", s09_policy_true),
    Rule("S10", "P1", "data", "AGENT", "Security definer function callable over RPC", s10_security_definer),
    Rule("S11", "P1", "data", "AGENT", "View without security_invoker", s11_view_without_invoker),
    Rule("S12", "P1", "data", "AGENT", "Public storage bucket", s12_public_bucket),
    Rule("S13", "P0", "data", "AGENT", "Firebase rules open to everyone", s13_firebase_open),
    Rule("S14", "P1", "data", "AGENT", "Client writes its own plan, credits or role", s14_client_writes_limits),
    Rule("S15", "P1", "auth", "AGENT", "Auth token stored in web storage", s15_token_in_storage),
    Rule("S16", "P1", "abuse", "AGENT", "Raw HTML sink (XSS risk)", s16_xss_sink),
    Rule("S17", "P0", "abuse", "AGENT", "Stripe webhook without signature check", s17_unverified_webhook),
    Rule("S18", "P1", "abuse", "AGENT", "SQL built by string interpolation", s18_sql_interpolation),
    Rule("S19", "P1", "ops", "AGENT", "CORS open to any origin", s19_cors_open),
    Rule("S20", "P1", "ops", "AGENT", "Debug mode or public source maps in production", s20_debug_in_prod),
    Rule("S21", "P1", "auth", "AGENT", "Password hashed with a fast hash", s21_weak_password_hash),
    Rule("S22", "P2", "abuse", "AGENT", "Server routes without rate limiting", s22_no_rate_limit),
    Rule("S23", "P2", "abuse", "AGENT", "Signup without bot protection", s23_no_bot_protection, ("signup",)),
    Rule("S24", "P2", "auth", "AGENT", "Open redirect from a query parameter", s24_open_redirect),
    Rule("L01", "P1", "legal", "AGENT", "Google Fonts loaded from Google's servers", l01_google_fonts),
    Rule("L02", "P1", "legal", "AGENT", "Tracker without a consent tool", l02_tracker_without_consent),
    Rule("L03", "P1", "legal", "AGENT", "Session replay recording", l03_session_replay),
    Rule("L04", "P1", "legal", "HUMAN", "Legal page missing", l04_legal_page_missing),
    Rule("L05", "P1", "legal", "AGENT", "Pre-checked consent box", l05_prechecked_consent),
    Rule("L06", "P2", "legal", "HUMAN", "Signup without an age check", l06_no_age_check, ("signup",)),
    Rule("L07", "P2", "legal", "AGENT", "AI features need disclosure and spend caps", l07_ai_disclosure),
    Rule("L08", "P1", "legal", "AGENT", "Signup without account deletion", l08_no_account_deletion, ("signup",)),
    Rule("L09", "P1", "legal", "AGENT", "Image without alt text", l09_img_without_alt),
    Rule("L10", "P2", "legal", "AGENT", "Focus outline removed", l10_focus_outline_removed),
    Rule("L11", "P2", "legal", "AGENT", "Root html element without lang", l11_html_without_lang),
    Rule("L12", "P1", "legal", "HUMAN", "Email sending without unsubscribe", l12_no_unsubscribe),
    Rule("L13", "P1", "legal", "AGENT", "Subscription without renewal terms", l13_no_renewal_terms),
    Rule("L14", "P1", "legal", "AGENT", "User content without a report action", l14_ugc_without_report),
    Rule("D01", "P3", "design", "AGENT", "Purple/blue gradient", d01_purple_gradient),
    Rule("D02", "P3", "design", "AGENT", "Gradient text", d02_gradient_text),
    Rule("D03", "P3", "design", "AGENT", "Glassmorphism everywhere", d03_glassmorphism),
    Rule("D04", "P3", "design", "AGENT", "Colored left-border cards", d04_left_border_cards),
    Rule("D05", "P3", "design", "AGENT", "20+ distinct lucide icons", d05_many_icons),
    Rule("D06", "P3", "design", "AGENT", "Inter as the typeface", d06_inter_font),
    Rule("D07", "P3", "copy", "AGENT", "Emoji in user-facing copy", d07_emoji),
    Rule("D08", "P3", "design", "AGENT", "Scroll-reveal animation everywhere", d08_scroll_reveal),
    Rule("D09", "P3", "design", "AGENT", "Grid, dot or noise filler texture", d09_filler_texture),
    Rule("D10", "P3", "design", "AGENT", "Custom cursor or spotlight effect", d10_cursor_effect),
    Rule("D11", "P3", "copy", "AGENT", "Em dashes in user-facing copy", d11_em_dashes),
    Rule("D12", "P3", "copy", "AGENT", "Marketing buzzwords", d12_buzzwords),
    Rule("D13", "P1", "copy", "HUMAN", "Placeholder content", d13_placeholder_content),
    Rule("D14", "P1", "legal", "HUMAN", "Unverifiable social proof", d14_social_proof),
    Rule("D15", "P2", "seo", "AGENT", "Default scaffold title or assets", d15_scaffold_metadata),
    Rule("D16", "P2", "seo", "AGENT", "Missing robots, sitemap, 404, OG image or favicon", d16_seo_basics),
    Rule("D17", "P2", "seo", "AGENT", "More than one h1 in a file", d17_multiple_h1),
    Rule("D18", "P3", "seo", "HUMAN", "AI crawlers blocked in robots.txt", d18_ai_crawlers_blocked),
    Rule("D19", "P3", "design", "AGENT", "Untouched shadcn/ui theme", d19_stock_shadcn_theme),
    Rule("M01", "P0", "store", "AGENT", "Capacitor server.url left in config", m01_capacitor_server_url, ("native",)),
    Rule("M02", "P1", "store", "HUMAN", "Webview wrapper with little native value", m02_thin_wrapper, ("native",)),
    Rule("M03", "P0", "store", "AGENT", "Native signup without in-app deletion", m03_no_in_app_deletion,
         ("native", "signup")),
    Rule("M04", "P1", "store", "AGENT", "Third-party login without Sign in with Apple", m04_no_sign_in_with_apple,
         ("native",)),
    Rule("M05", "P1", "store", "HUMAN", "Web checkout in a native app, no IAP", m05_web_checkout_no_iap, ("native",)),
    Rule("M06", "P1", "store", "AGENT", "In-app purchases without restore", m06_no_restore_purchases, ("native",)),
    Rule("M07", "P0", "store", "AGENT", "Android targetSdk below the Play floor", m07_target_sdk, ("native",)),
    Rule("M08", "P1", "store", "AGENT", "Sensitive Android permission", m08_sensitive_permission, ("native",)),
    Rule("M09", "P1", "store", "AGENT", "iOS privacy manifest missing", m09_privacy_manifest, ("native",)),
    Rule("M10", "P2", "store", "AGENT", "Vague iOS permission prompt", m10_usage_descriptions, ("native",)),
    Rule("M11", "P3", "store", "HUMAN", "iPad supported: layout gets reviewed", m11_ipad_supported, ("native",)),
]
RULE_IDS = {r.id for r in RULES}

GATES = {
    "git": ("is_git", "not a git repo"),
    "signup": ("has_signup", "no signup flow found (signUp(, createUserWithEmailAndPassword, /signup or /register)"),
    "native": ("has_native", "no native app found (Capacitor, Cordova, Expo, React Native, Flutter, ios/, android/)"),
}


def select_rules(only: str | None) -> list[Rule]:
    """--only accepts rule IDs and area names, comma-separated."""
    if not only:
        return list(RULES)
    wanted = [t.strip() for t in only.split(",") if t.strip()]
    unknown = [t for t in wanted if t.upper() not in RULE_IDS and t.lower() not in AREAS]
    if unknown:
        raise ValueError(f"unknown rule or area: {', '.join(unknown)}")
    ids = {t.upper() for t in wanted if t.upper() in RULE_IDS}
    areas = {t.lower() for t in wanted if t.lower() in AREAS}
    return [r for r in RULES if r.id in ids or r.area in areas]


# --- Suppressions --------------------------------------------------------------
#
# The owner can accept a finding in code, the way `# nosec` or `eslint-disable`
# work. A reason is required, and every suppression is listed in the report
# notes, so accepting a finding stays visible instead of making it disappear.
#
#   <!-- polish-website-ignore D12 demo text for the rule bench -->   this line and the next
#   // polish-website-ignore-file S02 fixtures use fake keys         the whole file
#   .polish-website-ignore at the scan root, one per line:           <ID> <path glob> <reason>
#       D06 * Inter is the brand typeface

IGNORE_COMMENT = re.compile(
    r"polish-website-ignore(?P<file>-file)?[ \t]+(?P<ids>[A-Z]\d{2}(?:[ \t]*,[ \t]*[A-Z]\d{2})*)(?P<reason>[^\n]*)")
COMMENT_TAIL = re.compile(r"\s*(?:-->|\*/\s*\}?|\}|#)?\s*$")
WHERE_PATH = re.compile(r"^(?P<path>[^\s:]+)(?::(?P<line>\d+))?")


def _reason(raw: str) -> str:
    return COMMENT_TAIL.sub("", raw).strip(" \t-:—")


def apply_suppressions(repo: Repo, findings: list[Finding]) -> tuple[list[Finding], list[str]]:
    """Drop findings the owner accepted with a reason. Return (kept, notes)."""
    line_rules: dict[tuple[str, int], tuple[set[str], str]] = {}
    file_rules: dict[str, list[tuple[set[str], str]]] = {}
    glob_rules: list[tuple[set[str], str, str]] = []
    notes: list[str] = []

    for f in repo.files:
        if "polish-website-ignore" not in f.text:
            continue
        for m in IGNORE_COMMENT.finditer(f.text):
            ids = {i.strip() for i in m.group("ids").split(",")}
            reason = _reason(m.group("reason"))
            at = f"{f.rel}:{f.line_at(m.start())}"
            if len(re.findall(r"[A-Za-z]{2,}", reason)) < 2:
                notes.append(f"polish-website-ignore at {at} has no reason (two words or more), so it was not applied")
                continue
            if m.group("file"):
                file_rules.setdefault(f.rel, []).append((ids, reason))
            else:
                line = f.line_at(m.start())
                for n in (line, line + 1):
                    line_rules[(f.rel, n)] = (ids, reason)

    ignore_file = repo.root / ".polish-website-ignore"
    if ignore_file.is_file():
        for n, raw in enumerate(ignore_file.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            parts = raw.split(None, 2)
            if not parts or parts[0].startswith("#"):
                continue
            if len(parts) < 3 or not re.fullmatch(r"[A-Z]\d{2}(?:,[A-Z]\d{2})*", parts[0]) or len(re.findall(r"[A-Za-z]{2,}", parts[2])) < 2:
                notes.append(f".polish-website-ignore line {n} needs `<ID> <path glob> <reason>`, so it was not applied")
                continue
            glob_rules.append((set(parts[0].split(",")), parts[1], parts[2].strip()))

    kept: list[Finding] = []
    dropped: list[str] = []
    for finding in findings:
        m = WHERE_PATH.match(finding.where)
        path, line = (m.group("path"), int(m.group("line") or 0)) if m else ("", 0)
        reason = None
        ids_reason = line_rules.get((path, line))
        if ids_reason and finding.id in ids_reason[0]:
            reason = ids_reason[1]
        for ids, why in file_rules.get(path, []):
            if reason is None and finding.id in ids:
                reason = why
        for ids, pattern, why in glob_rules:
            if reason is None and finding.id in ids and fnmatch.fnmatch(path, pattern):
                reason = why
        if reason is None:
            kept.append(finding)
        else:
            dropped.append(f"{finding.id} {finding.where.split(' ')[0]} ({reason})")
    if dropped:
        shown = "; ".join(dropped[:10]) + (f"; and {len(dropped) - 10} more" if len(dropped) > 10 else "")
        notes.append(f"{len(dropped)} finding(s) suppressed by the owner: {shown}")
    return kept, notes


def run(root: Path, target: str, rules: list[Rule]) -> tuple[list[Finding], list[str]]:
    repo = Repo(root, target)
    findings: list[Finding] = []
    skipped: dict[str, list[str]] = {}
    for rule in rules:
        reason = next((GATES[g][1] for g in rule.needs if not getattr(repo, GATES[g][0])), None)
        if reason:
            skipped.setdefault(reason, []).append(rule.id)
            continue
        findings.extend(rule.check(repo, rule))
    findings, suppressed = apply_suppressions(repo, findings)
    notes = [f"{reason}: {', '.join(ids)} skipped" for reason, ids in skipped.items()]
    if not repo.is_git and any(r.id == "S05" for r in rules):
        notes.append("not a git repo: S05 read .gitignore files directly instead of asking git")
    return findings, notes + repo.notes + suppressed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Static launch-readiness scan of a repo.")
    parser.add_argument("path", nargs="?", default=".", help="repo to scan (default .)")
    parser.add_argument("--only", help="comma-separated rule IDs or areas, e.g. S08,S09 or secrets,data")
    add_output_args(parser)
    args = parser.parse_args(argv)
    if args.list_rules:
        emit(rules_table(RULES, args.format), args.out)
        return 0
    try:
        rules = select_rules(args.only)
    except ValueError as exc:
        print(f"scan.py: {exc}", file=sys.stderr)
        return 2
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"scan.py: not a directory: {args.path}", file=sys.stderr)
        return 2
    try:
        findings, notes = run(root, args.path, rules)
        emit(render(TOOL, args.path, findings, args.format, notes), args.out)
    except OSError as exc:
        print(f"scan.py: {exc}", file=sys.stderr)
        return 2
    return exit_code(findings, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())
