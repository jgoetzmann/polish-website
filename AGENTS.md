# Guide for agents

This file explains how to change polish-website without breaking its
package, its prompts, or the values that must agree across files.

## What this repo contains
The skill is Markdown plus two stdlib-only Python scripts. `SKILL.md` is the
prompt the orchestrating agent reads. `agents/*.md` are prompts pasted verbatim
into subagents. `scripts/scan.py` and `scripts/probe.py` gather the first
evidence. Keep the skill portable: don't write instructions that tie it to one
agent tool.

## Key files
- `SKILL.md` is the source of truth. It holds the seven phases, the finding
  shape, the severity table, the attack list, and the launch gate.
- `agents/security-auditor.md`, `legal-auditor.md`, `design-auditor.md`, and
  `store-auditor.md` are the Phase 2 read-only auditors. Each carries its own
  checklist, because a subagent never sees `SKILL.md`.
- `agents/stranger.md` is the blind reviewer. It gets a URL and nothing else.
- `agents/fixer.md` is Phase 4. One fixer per file cluster.
- `agents/attacker.md` is the Phase 5 black-box test against staging.
- `scripts/_common.py` holds the finding shape, redaction, and secret patterns
  that both scripts share.
- `scripts/scan.py` is the static repo scan. `scripts/probe.py` is the live URL
  probe. Their tests are `scripts/test_scan.py` and `scripts/test_probe.py`, and
  `scripts/selftest.py` runs both.
- `scripts/validate-package.py` checks package files and shared values.
- `docs/RULES.md` is generated from the scripts. Never edit it by hand.
- `docs/BUILD-POLISH-WEBSITE.md` is the design rationale. Read it before you change
  a mechanic.
- `docs/SOURCES.md` records where each dated claim came from and when it was
  last checked.
- `web/index.html` is the landing page, deployed by `vercel.json`.
  `web/SKILL.md` is generated at deploy time and is gitignored.

## Rules for changes
- **Shared blocks.** The finding shape and the severity table appear in
  `SKILL.md` and in every finding-writing agent. The attack list appears in
  `SKILL.md` and `agents/attacker.md`. All copies must stay byte-identical. The
  validator compares them, and it checks that `_common.Finding.markdown()`
  prints the same labels.
- **Agent prompts.** `agents/*.md` must never say "the skill," reference
  `SKILL.md`, or use `$SKILL_DIR`. They may reference files under
  `.polish-website/`, which the orchestrator always provides.
- **Rules need a failing case.** Every rule ID in `scan.py` and `probe.py` needs a
  `test_<ID>_...` method that plants the defect and watches the rule fire. Each
  script also has a clean fixture that must produce zero findings. A rule that
  flags honest code teaches people to skim the report, so a new false positive
  gets a negative test in the same commit as its fix.
- **Scripts never leak.** No script may print a secret value or a row of user
  data. Evidence goes through `redact()`. `probe.py` only sends GET and HEAD, and
  only to the target origin, except Supabase under `--anon-read`.
- **Suppressions are the owner's.** `polish-website-ignore` comments and
  `.polish-website-ignore` lines need a reason, and every applied suppression is
  printed in the notes. No agent prompt may tell an agent to add one. This
  repo's own `.polish-website-ignore` covers only `scripts/`, whose rules and
  tests contain the patterns they look for.
- **Stdlib only.** The scripts must run on a bare `python3` (3.9 or newer) with no
  install step.
- **Rule IDs.** S is security, L is legal, D is design, copy, and SEO, M is the
  mobile stores, and W is the live probe. A1 through A10 belong to the attack
  list. Never reuse a retired ID.
- **Dated claims.** Any penalty figure, deadline, API level, or store rule gets a
  row in `docs/SOURCES.md` with its source and the date it was checked. Figures
  in prompts are maximums that set priority, never predictions.
- **Version.** Keep one version in `SKILL.md` `metadata.version`, the first
  README version entry, and `.claude-plugin/plugin.json`.
- **Size.** `SKILL.md` must stay at 350 lines or fewer. Detail belongs in an
  agent prompt.
- **Dogfood.** `python3 scripts/scan.py web --fail-on P3` must pass. The landing
  page for an audit that flags AI tells can't have any.
- **Checks.** Before publishing, run `python3 scripts/validate-package.py`,
  `python3 scripts/selftest.py`, `npx skills add . --list`, and
  `claude plugin validate .`.

## Releasing
1. Bump the version in `SKILL.md`, `README.md`, and `.claude-plugin/plugin.json`.
2. Add the README version note as the first entry in the list.
3. Run the checks above.
4. Push a `vX.Y.Z` tag. `.github/workflows/release.yml` validates the package,
   asserts the tag matches `metadata.version`, builds the ZIP, and publishes the
   release with the README notes as the body.

## Writing style
Use Plain Language in code comments, prompts, documentation, descriptions,
validation messages, and progress reports.

Plain Language governs grammar, never content — never replace a number, a
command, or a named failure with a common word, and where the two conflict the
number wins.
- Lead with the main point.
- Use common words and active voice.
- Keep sentences and paragraphs short.
- Use one term for the same item.
- Use `must` for requirements.
- Use headings, lists, and tables when they help the reader.
- Remove repeated or unnecessary words.
- Limit acronyms and explain technical terms.
- Avoid double negatives.
- Keep exact identifiers, commands, paths, schema fields, quotations, watched phrases, and behavior-bearing examples.
- Keep the full technical meaning.

## Editing the skill
- Keep the YAML metadata valid.
- Treat the prompt below the metadata as the product.
- Prefer a short, clear instruction over another exception or repeated explanation.
- Write every mechanical procedure as a runnable command, a script rule, or a
  countable criterion, not as prose advice. If a step needs judgment and has no
  evidence requirement, it will be skipped.
