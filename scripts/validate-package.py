#!/usr/bin/env python3
"""Check the polish-website package files without external dependencies.

Most checks hold shared values in agreement: the finding shape, the severity
table and the attack list are copied on purpose into SKILL.md and the agent
prompts, because each agent is pasted verbatim into a subagent that never sees
SKILL.md. A copy that drifts is a finding the triage step can't parse.

Run with --write-rules to regenerate docs/RULES.md from the scripts.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import textwrap
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
SKILL_PATH = ROOT / "SKILL.md"
AGENT_DIR = ROOT / "agents"
RULES_DOC = ROOT / "docs" / "RULES.md"

WALK_SKIP = {".git", ".vercel", "__pycache__", "node_modules", ".polish-website"}
DEPLOY_SKILL = ROOT / "web" / "SKILL.md"
PLACEHOLDER_SKIP = {Path(__file__).resolve(), DEPLOY_SKILL}

PHASES = list(range(7))
MAX_SKILL_LINES = 350
# Agents that write findings carry the finding shape and the severity table verbatim.
FINDING_AGENTS = ("security-auditor", "legal-auditor", "design-auditor", "store-auditor", "stranger", "attacker")
BANNED_IN_AGENTS = ("SKILL.md", "this skill", "the skill", "$SKILL_DIR")
# Scripts a user runs. Each must be routed from SKILL.md, or nobody runs it.
USER_SCRIPTS = ("scan.py", "probe.py")
PLAIN_LANGUAGE_RULES = (
    "## Writing style",
    "Lead with the main point.",
    "Use common words and active voice.",
    "Keep sentences and paragraphs short.",
    "Use `must` for requirements.",
    "Keep the full technical meaning.",
)
PHASE_ROW = re.compile(r"^\|[ \t]*([0-6])[ \t]*\|([^|\n]*)\|([^|\n]*)\|[ \t]*$", re.MULTILINE)
FENCE_LINE = re.compile(r"[ \t]{0,3}(`{3,}|~{3,})")


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def read(path: Path) -> str:
    if not path.is_file():
        raise SystemExit(f"{rel(path)} is missing. Create it before cutting a release.")
    return path.read_text(encoding="utf-8")


def load_json(path: Path) -> dict:
    try:
        return json.loads(read(path))
    except json.JSONDecodeError as err:
        raise SystemExit(f"{rel(path)} is not valid JSON ({err}). Fix the syntax.") from err


def load_module(name: str):
    sys.path.insert(0, str(SCRIPTS))
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    if spec is None or spec.loader is None:
        raise SystemExit(f"scripts/{name}.py can't be loaded. Check that it exists.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses look their module up here
    spec.loader.exec_module(module)
    return module


def split_fences(text: str) -> tuple[str, list[str]]:
    """Return the prose, with fenced blocks blanked out, plus the block bodies."""
    kept: list[str] = []
    blocks: list[list[str]] = []
    fence = ""
    for line in text.split("\n"):
        hit = FENCE_LINE.match(line)
        if not fence:
            if hit:
                fence = hit.group(1)
                blocks.append([])
            kept.append("" if hit else line)
        elif hit and hit.group(1)[0] == fence[0] and len(hit.group(1)) >= len(fence):
            fence = ""
            kept.append("")
        else:
            blocks[-1].append(line)
            kept.append("")
    return "\n".join(kept), ["".join(f"{line}\n" for line in body) for body in blocks]


def fenced_block(text: str, needle: str, where: str) -> str:
    """Return the body of the fenced block containing needle, dedented, so a block
    nested in a list item compares equal to the same block at the top level."""
    for body in split_fences(text)[1]:
        if needle in body:
            return textwrap.dedent(body)
    raise SystemExit(f"{where} has no fenced code block containing `{needle}`. Add one.")


def phase_table(text: str, where: str) -> dict[int, str]:
    rows = PHASE_ROW.findall(split_fences(text)[0])
    if not rows:
        raise SystemExit(f"{where} has no phase table. Every row must read `| 0 | what | none |`: three cells, outside any code fence.")
    seen = [int(phase) for phase, _, _ in rows]
    if seen != PHASES:
        raise SystemExit(f"{where} phase table lists phases {seen}. Give it one row per phase, {PHASES}, in order.")
    return {int(phase): " ".join(agents.split()) for phase, _, agents in rows}


def rule_fields(rule) -> dict:
    get = rule.get if isinstance(rule, dict) else (lambda k: getattr(rule, k, None))
    return {k: get(k) for k in ("id", "severity", "area", "owner", "title")}


def rules_doc(scan, probe) -> str:
    return (
        "# Rules\n\n"
        "Every check the two scripts run. Generated from the scripts, so don't edit it\n"
        "by hand. Regenerate it with `python3 scripts/validate-package.py --write-rules`.\n\n"
        "Severity and owner are the defaults. A rule can report higher or lower when\n"
        "the evidence says so. For example, S06 is P0 in a `'use client'` file and P1\n"
        "otherwise.\n\n"
        "## scan.py — static repo scan\n\n"
        f"{scan.rules_table(scan.RULES, 'md')}\n"
        "## probe.py — live URL probe\n\n"
        f"{probe.rules_table(probe.RULES, 'md')}"
    )


SKILL = read(SKILL_PATH)
README = read(ROOT / "README.md")
AGENTS = read(ROOT / "AGENTS.md")
PLUGIN = load_json(ROOT / ".claude-plugin" / "plugin.json")
MARKETPLACE = load_json(ROOT / ".claude-plugin" / "marketplace.json")
SKILL_PROSE, README_PROSE, AGENTS_PROSE = (split_fences(t)[0] for t in (SKILL, README, AGENTS))
COMMON = load_module("_common")
SCAN = load_module("scan")
PROBE = load_module("probe")

if "--write-rules" in sys.argv:
    RULES_DOC.write_text(rules_doc(SCAN, PROBE), encoding="utf-8")
    print(f"Wrote {rel(RULES_DOC)}")

# 1. SKILL.md opens with YAML metadata.
m = re.match(r"---\n(.*?)\n---\n", SKILL, re.DOTALL)
if not m:
    raise SystemExit("SKILL.md must open with YAML metadata fenced by `---` lines.")
front = m.group(1)
for key in ("name", "description", "license"):
    if not re.search(rf"^{key}:", front, re.M):
        raise SystemExit(f"SKILL.md frontmatter is missing `{key}:`. Add it.")
if not re.search(r"^name:[ \t]*polish-website[ \t]*$", front, re.M):
    raise SystemExit("SKILL.md `name:` must be polish-website, matching plugin.json.")

# 2. No unsupported frontmatter fields.
if bad := [f for f in ("compatibility", "allowed-tools") if re.search(rf"^[ \t]*{f}[ \t]*:", front, re.M)]:
    raise SystemExit(f"SKILL.md frontmatter uses unsupported field(s): {', '.join(bad)}. Delete them.")

# 3. SKILL.md, README.md and plugin.json agree on one version.
meta = re.search(r"^metadata:[ \t]*$", front, re.M)
sv = re.search(r'^[ \t]+version:[ \t]*"?(\d+\.\d+\.\d+)"?', front[meta.end():], re.M) if meta else None
rv = re.search(r"^- \*\*(\d+\.\d+\.\d+)\*\*", README_PROSE, re.M)
if not sv or not rv:
    raise SystemExit('SKILL.md needs `version: "X.Y.Z"` under `metadata:`, and README.md a history entry `- **X.Y.Z** — ...`.')
versions = {sv.group(1), rv.group(1), PLUGIN.get("version", "")}
if len(versions) > 1:
    raise SystemExit(f"Version disagreement: SKILL.md={sv.group(1)}, README.md={rv.group(1)}, plugin.json={PLUGIN.get('version')}. Set all three to one number.")
version = sv.group(1)

# 4. Exactly one real SKILL.md, at the repo root.
if SKILL_PATH.is_symlink():
    raise SystemExit("SKILL.md is a symlink. Replace it with the real file; packagers don't follow links.")
extra = sorted(rel(p) for p in ROOT.rglob("SKILL.md")
               if p not in (SKILL_PATH, DEPLOY_SKILL) and not WALK_SKIP.intersection(p.relative_to(ROOT).parts[:-1]))
if extra:
    raise SystemExit(f"Extra SKILL.md copies found: {', '.join(extra)}. The package ships exactly one, at the root.")

# 5-6. Plugin manifests.
if PLUGIN.get("skills") != ["./"]:
    raise SystemExit('plugin.json `skills` must be exactly ["./"] so the root SKILL.md loads.')
entries = MARKETPLACE.get("plugins") or []
if len(entries) != 1:
    raise SystemExit(f"marketplace.json lists {len(entries)} plugins. It must list exactly one.")
if drift := [k for k in ("name", "description", "license", "keywords") if entries[0].get(k) != PLUGIN.get(k)]:
    raise SystemExit(f"marketplace.json disagrees with plugin.json on: {', '.join(drift)}. Copy the plugin.json values.")

# 7. SKILL.md is loaded on every run, so its length is a running cost.
if (n := len(SKILL.splitlines())) > MAX_SKILL_LINES:
    raise SystemExit(f"SKILL.md is {n} lines, over the {MAX_SKILL_LINES}-line limit. Move detail into an agents/ prompt.")

# 8-10. Phases: headings in order, and the two tables agree.
headings = [int(x) for x in re.findall(r"^## Phase (\d+) — ", SKILL_PROSE, re.M)]
if headings != PHASES:
    raise SystemExit(f"SKILL.md phase headings are {headings}. Write `## Phase N — Title` for each of {PHASES}, in order.")
skill_phases = phase_table(SKILL, "SKILL.md")
readme_phases = phase_table(README, "README.md")
if mismatch := [p for p in PHASES if readme_phases[p] != skill_phases[p]]:
    raise SystemExit(f"README.md phase table disagrees with SKILL.md on phase(s) {mismatch}. Copy the SKILL.md Agents values.")

# 11. Agent prompts and SKILL.md references match, both directions.
referenced = set(re.findall(r"agents/([A-Za-z0-9._-]+)\.md", SKILL))
on_disk = {p.stem for p in AGENT_DIR.glob("*.md")}
if missing := sorted(referenced - on_disk):
    raise SystemExit(f"SKILL.md references agent prompt(s) that don't exist: {', '.join(missing)}.")
if orphan := sorted(on_disk - referenced):
    raise SystemExit(f"agents/ holds prompt(s) SKILL.md never references: {', '.join(orphan)}.")
if missing := sorted(set(FINDING_AGENTS) - on_disk):
    raise SystemExit(f"Finding-writing agent(s) missing from agents/: {', '.join(missing)}.")

# 12. Agent prompts stand alone.
for agent in sorted(AGENT_DIR.glob("*.md")):
    lowered = read(agent).lower()
    if leaks := [p for p in BANNED_IN_AGENTS if p.lower() in lowered]:
        raise SystemExit(f"{rel(agent)} mentions {', '.join(map(repr, leaks))}. It is pasted verbatim into a subagent that never saw the skill; rewrite it to stand alone.")

# 13. The finding shape and severity table are byte-identical wherever they appear.
FORMAT = fenced_block(SKILL, "### <id> · <severity> · <area> · <owner>", "SKILL.md")
SEVERITY = fenced_block(SKILL, "P0  exploitable now", "SKILL.md")
for name in FINDING_AGENTS:
    text = read(AGENT_DIR / f"{name}.md")
    for label, block, needle in (("finding shape", FORMAT, "### <id> ·"), ("severity table", SEVERITY, "P0  ")):
        theirs = fenced_block(text, needle, f"agents/{name}.md")
        if theirs != block:
            raise SystemExit(f"The {label} in agents/{name}.md differs from SKILL.md.\n--- SKILL.md ---\n{block}--- agents/{name}.md ---\n{theirs}Make them byte-identical.")

# 14. What the scripts print matches that shape, label for label.
sample = COMMON.Finding("X1", "P0", "secrets", "AGENT", "w", "e", "y", "f", "v").markdown()
shape_labels = [line.split(":", 1)[0] for line in FORMAT.splitlines()[1:]]
printed_labels = [line.split(":", 1)[0] for line in sample.splitlines()[1:]]
if shape_labels != printed_labels or tuple(shape_labels) != COMMON.FIELD_LABELS:
    raise SystemExit(f"Finding labels disagree: SKILL.md {shape_labels}, _common.Finding.markdown() {printed_labels}, FIELD_LABELS {list(COMMON.FIELD_LABELS)}.")
table_levels = tuple(line.split()[0] for line in SEVERITY.splitlines() if line.strip())
if table_levels != COMMON.SEVERITIES:
    raise SystemExit(f"Severity table levels {table_levels} disagree with _common.SEVERITIES {COMMON.SEVERITIES}.")
area_line = re.search(r"by area in this order: ([a-z, \n]+)\.", SKILL_PROSE)
areas = tuple(a.strip() for a in re.split(r",\s*", area_line.group(1).replace("\n", " "))) if area_line else ()
if areas != COMMON.AREAS:
    raise SystemExit(f"SKILL.md triage area order {areas} disagrees with _common.AREAS {COMMON.AREAS}.")

# 15. The attack list is identical in SKILL.md and the attacker prompt.
attack = fenced_block(SKILL, "A1  anonymous", "SKILL.md")
if fenced_block(read(AGENT_DIR / "attacker.md"), "A1  anonymous", "agents/attacker.md") != attack:
    raise SystemExit("The A1-A10 attack list differs between SKILL.md and agents/attacker.md. Make them byte-identical.")
if [line.split()[0] for line in attack.splitlines() if line.strip()] != [f"A{i}" for i in range(1, 11)]:
    raise SystemExit("The attack list must be exactly A1 through A10, one per line.")

# 16. Rules: unique, valid, each seen failing in a test, and every ID SKILL.md cites exists.
all_ids: set[str] = set()
for module, test_file in ((SCAN, "test_scan.py"), (PROBE, "test_probe.py")):
    fields = [rule_fields(r) for r in module.RULES]
    ids = [f["id"] for f in fields]
    if dup := sorted({i for i in ids if ids.count(i) > 1}):
        raise SystemExit(f"{module.__name__}.py has duplicate rule IDs: {', '.join(dup)}.")
    for f in fields:
        if f["severity"] not in COMMON.SEVERITIES or f["area"] not in COMMON.AREAS or f["owner"] not in COMMON.OWNERS or not f["title"]:
            raise SystemExit(f"{module.__name__}.py rule {f['id']} has an invalid severity, area, owner, or empty title: {f}.")
    tests = read(SCRIPTS / test_file)
    if untested := [i for i in ids if not re.search(rf"\btest_{re.escape(i)}_", tests)]:
        raise SystemExit(f"scripts/{test_file} has no `test_<ID>_...` case for: {', '.join(untested)}. A rule nobody has seen fire is asserted, not tested.")
    all_ids.update(ids)
if unknown := sorted(set(re.findall(r"\b([SLDMW]\d{2})\b", SKILL_PROSE + "".join(split_fences(SKILL)[1]))) - all_ids):
    raise SystemExit(f"SKILL.md cites rule ID(s) no script defines: {', '.join(unknown)}.")

# 17. Every user-facing script is routed from SKILL.md, and every script SKILL.md names exists.
for script in USER_SCRIPTS:
    if f"scripts/{script}" not in SKILL:
        raise SystemExit(f"SKILL.md never tells anyone to run scripts/{script}. Route it, or delete it.")
for named in set(re.findall(r"scripts/([A-Za-z0-9_.-]+\.py)", SKILL)):
    if not (SCRIPTS / named).is_file():
        raise SystemExit(f"SKILL.md names scripts/{named}, which doesn't exist.")

# 18. docs/RULES.md matches the scripts.
if read(RULES_DOC) != rules_doc(SCAN, PROBE):
    raise SystemExit("docs/RULES.md is out of date with the scripts. Run `python3 scripts/validate-package.py --write-rules`.")

# 19. AGENTS.md carries the Plain Language rules.
if absent := [r for r in PLAIN_LANGUAGE_RULES if r not in AGENTS_PROSE]:
    raise SystemExit(f"AGENTS.md is missing Plain Language rule text: {'; '.join(absent)}.")

# 20. No placeholder tokens survive anywhere in the package.
for path in sorted(ROOT.rglob("*")):
    if not path.is_file() or path in PLACEHOLDER_SKIP or WALK_SKIP.intersection(path.relative_to(ROOT).parts[:-1]):
        continue
    try:
        body = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        continue
    if "REPLACE_ME" in body:
        raise SystemExit(f"{rel(path)} still contains REPLACE_ME. Replace it with the real value.")

print(f"polish-website package v{version} is valid ({len(all_ids)} rules)")
