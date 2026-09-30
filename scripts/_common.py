"""Shared pieces for scan.py and probe.py: the finding shape, redaction, and secret patterns.

Stdlib only, Python 3.9 or newer. Both scripts import this file, so a change here
changes the output of both. The finding shape must match the block in SKILL.md
and agents/*.md field for field; scripts/validate-package.py checks the labels.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from dataclasses import asdict, dataclass

# Order is priority. Severity sorts first, then area, so a report reads
# data exposure -> auth -> abuse -> legal -> store -> design without a second pass.
SEVERITIES = ("P0", "P1", "P2", "P3")
AREAS = ("secrets", "data", "auth", "abuse", "ops", "legal", "store", "design", "copy", "seo")
OWNERS = ("AGENT", "HUMAN")

FIELD_LABELS = ("Where", "Evidence", "Why", "Fix", "Verify")


@dataclass
class Finding:
    id: str
    severity: str
    area: str
    owner: str
    where: str
    evidence: str
    why: str
    fix: str
    verify: str

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"{self.id}: severity {self.severity!r} is not one of {SEVERITIES}")
        if self.area not in AREAS:
            raise ValueError(f"{self.id}: area {self.area!r} is not one of {AREAS}")
        if self.owner not in OWNERS:
            raise ValueError(f"{self.id}: owner {self.owner!r} is not one of {OWNERS}")
        for name in ("where", "evidence", "why", "fix", "verify"):
            value = " ".join(str(getattr(self, name)).split())
            if not value:
                raise ValueError(f"{self.id}: field {name!r} is empty")
            setattr(self, name, value)

    def markdown(self) -> str:
        return (
            f"### {self.id} · {self.severity} · {self.area} · {self.owner}\n"
            f"Where: {self.where}\n"
            f"Evidence: {self.evidence}\n"
            f"Why: {self.why}\n"
            f"Fix: {self.fix}\n"
            f"Verify: {self.verify}\n"
        )


def sort_key(f: Finding) -> tuple:
    return (SEVERITIES.index(f.severity), AREAS.index(f.area), f.id, f.where)


def counts(findings: list[Finding]) -> str:
    return ", ".join(f"{s} {sum(1 for f in findings if f.severity == s)}" for s in SEVERITIES)


def render(tool: str, target: str, findings: list[Finding], fmt: str, notes: list[str] | None = None) -> str:
    findings = sorted(findings, key=sort_key)
    notes = notes or []
    if fmt == "json":
        return json.dumps(
            {"tool": tool, "target": target, "notes": notes, "findings": [asdict(f) for f in findings]},
            indent=2,
            ensure_ascii=False,
        ) + "\n"
    head = f"# {tool}: {target}\n\n{len(findings)} findings ({counts(findings)})\n"
    body = "".join(f"\n{f.markdown()}" for f in findings)
    tail = "".join(f"\n> {n}" for n in notes)
    return head + body + (("\n" + tail.lstrip("\n") + "\n") if notes else "")


def exit_code(findings: list[Finding], fail_on: str) -> int:
    """0 when nothing is at or above fail_on, 1 when something is. fail_on 'none' never fails."""
    if fail_on == "none":
        return 0
    limit = SEVERITIES.index(fail_on)
    return 1 if any(SEVERITIES.index(f.severity) <= limit for f in findings) else 0


def add_output_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format", choices=("md", "json"), default="md", help="output format (default md)")
    parser.add_argument("--fail-on", choices=(*SEVERITIES, "none"), default="P0",
                        help="exit 1 if any finding is at or above this severity (default P0)")
    parser.add_argument("--out", help="also write the report to this file")
    parser.add_argument("--list-rules", action="store_true", help="print every rule and exit")


def emit(text: str, out: str | None) -> None:
    sys.stdout.write(text)
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text)


def rules_table(rules: list, fmt: str) -> str:
    """rules: objects or dicts with id, severity, area, owner, title."""
    rows = []
    for r in rules:
        get = r.get if isinstance(r, dict) else (lambda k, _r=r: getattr(_r, k))
        rows.append((get("id"), get("severity"), get("area"), get("owner"), get("title")))
    if fmt == "json":
        return json.dumps([dict(zip(("id", "severity", "area", "owner", "title"), row)) for row in rows], indent=2) + "\n"
    lines = ["| ID | Severity | Area | Owner | Check |", "|---|---|---|---|---|"]
    lines += [f"| {a} | {b} | {c} | {d} | {e} |" for a, b, c, d, e in rows]
    return "\n".join(lines) + "\n"


# --- Secrets -----------------------------------------------------------------

# Publishable keys are public by design and never match: Stripe pk_live_, the
# Supabase anon JWT and sb_publishable_, Firebase web config (AIza...).
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("stripe secret key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{16,}")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI API key", re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}")),
    ("Supabase secret key", re.compile(r"\bsb_secret_[A-Za-z0-9_\-]{20,}")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("SendGrid key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("database URL with password", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s:@/'\"`]+:[^\s@'\"`]+@[^\s'\"`]+")),
)

JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")

PLACEHOLDER = re.compile(
    r"x{4,}|your[_\-]|<[^>]*>|\.\.\.|example|changeme|placeholder|dummy|localhost|127\.0\.0\.1|"
    r"user:pass(?:word)?@|postgres:postgres@",
    re.I,
)


def redact(value: str) -> str:
    """Keep enough to identify a key, never enough to use it."""
    value = value.strip()
    if value.startswith("-----BEGIN"):
        return value
    if len(value) <= 12:
        return "****"
    return f"{value[:6]}…{value[-4:]} ({len(value)} chars)"


def jwt_payload(token: str) -> dict | None:
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        data = json.loads(base64.urlsafe_b64decode(part.encode("ascii")))
        return data if isinstance(data, dict) else None
    except (IndexError, ValueError, UnicodeDecodeError):
        return None


def jwt_role(token: str) -> str | None:
    payload = jwt_payload(token)
    role = payload.get("role") if payload else None
    return role if isinstance(role, str) else None


def find_secrets(text: str) -> list[tuple[str, str, int]]:
    """Return (kind, redacted value, offset) for every real-looking secret in text.

    A JWT counts only when its payload says role=service_role: the anon key is
    meant to ship to the browser and flagging it teaches people to skim.
    """
    hits: list[tuple[str, str, int]] = []
    for kind, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            if PLACEHOLDER.search(m.group(0)):
                continue
            hits.append((kind, redact(m.group(0)), m.start()))
    for m in JWT.finditer(text):
        if jwt_role(m.group(0)) == "service_role":
            hits.append(("Supabase service_role JWT", redact(m.group(0)), m.start()))
    return sorted(hits, key=lambda h: h[2])


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1
