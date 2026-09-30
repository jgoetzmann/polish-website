---
name: polish-website
description: |
  Polish an AI-built ("vibecoded") website or app before launch: audit and fix
  security, legal compliance, AI-looking design and copy, and App Store / Google
  Play readiness. Two scripts gather evidence first (a static repo scan and a live
  URL probe). Read-only auditors confirm it in parallel, a blind "stranger" and a
  black-box attacker check what is actually deployed, and fixes land by file
  ownership, each with a command that proves it worked. Use when the user is
  building, reviewing, hardening, launching, or submitting a site or app made with
  Claude, Cursor, Lovable, v0, Bolt, Replit, or similar. Also use when they say
  "polish-website" or "polish my site," or ask whether it is secure, legal,
  "ready to launch," or "looks AI-generated," or
  mention RLS, leaked keys, cookie banners, a privacy policy, ADA, or an App
  Store rejection, even if they name only one of these areas. Not legal advice,
  and not a substitute for a professional pentest of a system that holds money
  or health data.
license: MIT
metadata:
  version: "1.0.0"
---

# polish-website

Coding agents optimize for "it works," not "it's safe." A vibecoded app usually
runs fine. It can also serve its database to anyone holding the public key, carry
a service-role key in the JavaScript bundle, set a tracker before the cookie
banner loads, and look like every other template on the internet. The owner
finds out last, after an attacker, a regulator, an App Store reviewer, or a
visitor who closed the tab.

This audit finds those problems first, fixes what code can fix, and hands the
owner a short list of what only a person can do.

Two ideas carry the weight.

**Evidence before opinion.** Every finding carries the line or command output
that proves it, and the command that proves it is fixed. The scripts run first
so the mechanical checks happen the same way every time. A finding with no
evidence is a guess, and triage drops it.

**Blind reviewers see what the public sees.** A reviewer who has read the code
knows what the app means to do. Attackers, regulators, store reviewers, and
visitors see only what it does. So the stranger never sees the repo, and the
attacker gets only a URL and two test accounts.

## Use it when

- A site or app is about to launch, or already has, and was built mostly by AI.
- The user names any one area: "is this secure," "do I need a cookie banner,"
  "make it not look AI-made," "will Apple accept this." Run that area, plus the
  secrets checks. They are cheap and they are where the P0s live.

## Don't use it when

- The system moves money, holds health records, or has more than a handful of
  engineers. Run the audit, then say plainly that it needs a professional
  pentest and a lawyer, not only this checklist.
- The user doesn't own the target. Never probe or attack a system without the
  owner's say-so. Refuse and say why.

## Setup

`$SKILL_DIR` is the directory this file is in. Run from the app's repo root:

```bash
mkdir -p .polish-website/findings .polish-website/notes
grep -qxF '.polish-website/' .gitignore 2>/dev/null || echo '.polish-website/' >> .gitignore
git switch -c polish-website 2>/dev/null || true
```

The ignore rule goes in **before** any file with evidence exists. Evidence can
include redacted key prefixes and file paths an attacker would like to have.

---

## Phase 0 — Map (no agents)

Read the repo and write `.polish-website/MAP.md` with exactly these keys, one per
line, each value followed by the file that proves it:

```
stack: next 15 app router, supabase, vercel — package.json
url.prod: https://example.app | none
url.staging: https://staging.example.app | none
accounts: yes — supabase auth, app/(auth)/signup/page.tsx
database: yes — supabase postgres, 14 tables in supabase/migrations/
storage: yes — 2 buckets, supabase/migrations/0004_storage.sql
payments: one-time | subscription | none — app/api/checkout/route.ts
ugc: yes — comments, app/posts/[id]/comments.tsx
email.marketing: no
analytics: posthog, sentry — app/providers.tsx
ai: yes — openai chat, app/api/chat/route.ts
native: none | capacitor | expo | react-native | flutter | planned
markets: US, EU
audience.minors: no
```

These keys decide what runs. A check whose trigger is `no` or `none` is skipped
and listed as skipped. Ask the user at most two questions, only for what the
code can't answer. Usually that is `markets` and `url.staging`. Also ask whether
you may run the live checks against the URL. Guess everything else and write
the guess down.

## Phase 1 — Scan (no agents)

```bash
python3 "$SKILL_DIR/scripts/scan.py" . --fail-on none --out .polish-website/scan.md
python3 "$SKILL_DIR/scripts/probe.py" "$URL" --fail-on none --out .polish-website/probe.md
```

`scan.py` reads the repo: secrets, RLS in migrations, client-side writes to
privilege columns, unverified webhooks, trackers, legal pages, AI tells, and
store config. `probe.py` reads the deployed site: bundles, headers, exposed
files, source maps, CORS, metadata, trackers in the first HTML. Use
`--list-rules` on either to see every check. Use `--only S08,W03` to rerun one.
To accept a finding, the owner adds a `polish-website-ignore <ID> <reason>` comment
on or above the line, or a line in `.polish-website-ignore` at the repo root. The
report's notes list every suppression. Agents never add one.

If the app uses Supabase and the owner confirms the project is theirs, check
what the public key can read. Use staging when it exists:

```bash
python3 "$SKILL_DIR/scripts/probe.py" "$STAGING_URL" --anon-read --only W14 --out .polish-website/anon.md
```

It only reads, and it prints row counts and column names, never values.

Also run the stack's own tools, but only the ones already installed. Ask before
installing anything:

```bash
npm audit --omit=dev                # or: pnpm audit --prod, pip-audit
gitleaks git -v                     # or: trufflehog git file://. — full history
supabase db advisors                # linked project; flags tables without RLS
```

**Stop rule:** a P0 in `secrets` (a live key in a bundle, in git, or on a URL)
goes to the user **now**, not at the report. Tell them which key to rotate and
where. Removing it from the code does not un-leak it.

## Phase 2 — Audit (fan out, read-only)

Launch in one batch. Each agent gets its file verbatim plus `MAP.md`,
`scan.md`, and `probe.md`:

| Agent | Covers | Skip when |
|---|---|---|
| `agents/security-auditor.md` | secrets, data, auth, abuse, ops | never |
| `agents/legal-auditor.md` | legal pages, consent, trackers, accessibility, feature-triggered law | never |
| `agents/design-auditor.md` | AI tells in visuals and copy, SEO basics | no web frontend |
| `agents/store-auditor.md` | App Store and Google Play | `native: none` |
| `agents/stranger.md` | the deployed site, blind | no URL; pass it rendered HTML or screenshots instead |

The stranger gets **only** the URL. Don't give it `MAP.md`, the repo, or the
scan output. For a large app (more than 15 tables or 30 routes), split the
security auditor in two: secrets and ops in one, data, auth and abuse in the
other.

Auditors never edit code. Every script finding in an auditor's areas must come
back **confirmed** (copied into its file, with a sharper Fix) or **dismissed**
(one line of reason). A script finding that comes back with neither was never
looked at, so rerun that auditor on it.

Every finding, from scripts and agents alike, uses this shape:

```
### <id> · <severity> · <area> · <owner>
Where: <path:line, URL, or dashboard page>
Evidence: <the offending line or the command and what it printed, secrets redacted>
Why: <what an attacker, regulator, store reviewer, or visitor does with this>
Fix: <the smallest change native to this stack>
Verify: <the command or test that proves it is fixed>
```

Severity is decided by this table, not by how alarming the finding sounds:

```
P0  exploitable now by an anonymous visitor, or a certain store rejection
P1  exploitable by a signed-in user, a legal duty with a per-incident penalty, or a likely store rejection
P2  hardening, or a legal or store item that depends on a fact the owner must confirm
P3  an AI tell, polish, or anything cosmetic
```

Owner is `AGENT` when a code change fixes it, and `HUMAN` when it needs a
dashboard, a store console, a lawyer, a key rotation, or content only the owner
knows.

## Phase 3 — Triage (no agents)

```bash
cat .polish-website/scan.md .polish-website/probe.md .polish-website/anon.md \
    .polish-website/findings/*.md 2>/dev/null > .polish-website/all.md
grep -c '^### ' .polish-website/all.md
```

1. **Dedupe** by `Where`. When two findings share a location, keep the higher
   severity and both pieces of evidence.
2. **Drop** any finding with an empty `Evidence` or `Verify`.
3. **Sort** by severity, then by area in this order: secrets, data, auth, abuse,
   ops, legal, store, design, copy, seo.
4. Write `.polish-website/REPORT.md`: a count per severity, every P0 and P1 in
   full, every `HUMAN` item as a checklist, and the fix plan. The fix plan groups
   `AGENT` findings into clusters that share no files.

**Show the user the P0 and P1 list and the fix plan, then wait.** Skip the wait
only if they already said "just fix it." Design changes that alter the look
need a yes of their own. Mechanical fixes don't: a page title, meta tags, alt
text, `lang`, a 404 page, robots, the sitemap.

## Phase 4 — Fix (fan out by file)

One fixer per cluster, `agents/fixer.md`. Pass it the cluster's findings and its
exclusive file list. Two fixers must never hold the same file in the same wave.

- **Wave 1:** every approved P0 and P1 `AGENT` finding.
- **Wave 2:** P2, and the P3 design and copy items the user approved.

Fixers write database changes as **new migration files**. They never apply them
to a live database. They never invent content: a placeholder testimonial gets
deleted or routed to the owner, never replaced with a better-sounding fake. They
run each finding's `Verify` after the fix and log the result to
`.polish-website/notes/fixes.md`.

Commit after each wave (`git commit -am "polish-website: wave N"`) so any wave can
roll back on its own.

## Phase 5 — Verify

1. Rerun `scan.py` and `probe.py` into `scan-after.md` and `probe-after.md`, and
   compare the finding IDs:

   ```bash
   diff <(grep -h '^### ' .polish-website/scan.md .polish-website/probe.md | sort) \
        <(grep -h '^### ' .polish-website/scan-after.md .polish-website/probe-after.md | sort)
   ```

2. **Attack pass** with `agents/attacker.md`, against staging or a local build,
   never production unless the owner says so in writing. Give it the URL, two
   test accounts the owner created, and `MAP.md`. No repo. It runs this list and
   returns PASS, FAIL, or N/A for each item, with the request and response as
   evidence:

   ```
   A1  anonymous visitor can't read or write any private row or file
   A2  user B can't read or change user A's data, by any id or path
   A3  a user can't raise their own credits, role, plan, or limits
   A4  no secret in any served bundle, source map, or exposed file
   A5  repeated wrong passwords get throttled before attempt 20
   A6  a forged or unsigned payment webhook is rejected and changes nothing
   A7  a script-bearing or oversized upload is rejected or served inert
   A8  admin routes and server actions refuse a non-admin session, server-side
   A9  a script payload in every text field renders as text
   A10 the AI endpoint refuses a user past their cap, and without a session
   ```

   Strix (`github.com/usestrix/strix`) is an optional second opinion. It needs
   Docker and the owner's own model key: `strix --target "$STAGING_URL"`.

3. **Fresh stranger.** After design fixes, run `agents/stranger.md` again in a
   **new** agent. The first one has seen the before, and remembering it is a
   form of reading the code.

## Phase 6 — Handoff (no agents)

Write `.polish-website/CHECKLIST.md`: every open `HUMAN` item, in severity order,
each with where to click or who to ask. Then report to the user in this order:
what was checked, what changed (with commits), what is still open, and what was
skipped and why.

---

## Phases

| Phase | What | Agents |
|---|---|---|
| 0 | Map the app and its triggers | none |
| 1 | Scan: scripts, then stack tools | none |
| 2 | Audit, read-only, in parallel | 3–6 |
| 3 | Triage and report; the user approves fixes | none |
| 4 | Fix by file ownership, in waves | 1/cluster |
| 5 | Verify: rerun, attack, fresh stranger | 2 |
| 6 | Handoff checklist | none |

## Launch gate

The app is ready when all of these hold:

- Zero open P0. Every P1 is fixed, or the owner accepted it in `REPORT.md` in
  their own words.
- Attack pass: A1 through A10 are each PASS or N/A, each with evidence.
- The fresh stranger finds no P0 or P1, and flags no claim as unverifiable that
  the owner can't back.
- Native apps: on a fresh install on iPhone, iPad, and Android, sign up, finish
  the core flow, buy, restore, and delete the account. Every step works, and
  every data category declared to the stores matches the SDK audit.

## Failure modes

| Tell | Cause | Fix |
|---|---|---|
| A script finding came back neither confirmed nor dismissed | The auditor skimmed | Rerun that auditor with the finding IDs named |
| The stranger mentions file names or components | It saw the repo | Discard it; rerun in a fresh agent with the URL only |
| Attack pass is all PASS with no request logged | It didn't test | Rerun; every PASS needs a request and a response |
| RLS is on and anonymous reads still work | `using (true)`, a view without `security_invoker`, or a public `security definer` function | Check S09, S10, and S11 |
| A fix adds a package for a one-line change | The fixer reached for a library | Revert; ask for the native fix |
| A placeholder became a plausible fake | The fixer invented content | Revert; route it to the owner as `HUMAN` |
| The same finding reappears after a wave | The fix patched a symptom, like the client check but not the policy | Reopen it; fix it where the data is enforced |

## Guardrails

- Read-only through Phase 3. Branch before Phase 4. Commit per wave.
- Live checks, `--anon-read`, and the attack pass run only against targets the
  owner confirms are theirs. Use staging first, test accounts only, and nothing
  destructive.
- Never print a secret or a user's data. Redact in every file and every message.
- Legal output is a starting point, not advice. Anything with a statutory
  penalty or a signature on it goes to a lawyer when the stakes are real.
- Penalty figures are statutory maximums or reported awards, not predictions.
  They set priority. Dated rules were fact-checked on 2026-09-29. Recheck
  anything marked "confirm," because store and platform rules move every year.

## Subagents

Pass each file verbatim, plus what that role needs. The reasoning behind every
rule is in `docs/BUILD-POLISH-WEBSITE.md`.

- `agents/security-auditor.md` — Phase 2. Add `MAP.md`, `scan.md`, `probe.md`.
- `agents/legal-auditor.md` — Phase 2. Same inputs.
- `agents/design-auditor.md` — Phase 2. Same inputs.
- `agents/store-auditor.md` — Phase 2, native apps only. Same inputs.
- `agents/stranger.md` — Phase 2 and Phase 5. Add the URL and nothing else.
- `agents/fixer.md` — Phase 4. Add the cluster's findings and its file list.
- `agents/attacker.md` — Phase 5. Add the URL, two test accounts, and `MAP.md`.

**No subagents available?** The audit still works. Run the scripts, then work
through each auditor file yourself as a checklist, in the Phase 2 table's order.
Two things are lost, so say so up front. The stranger can't be blind if you have
read the code, so ask the user to show the site to one real person. The attack
pass becomes a self-review, so treat it as weaker evidence.
