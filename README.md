# polish-website

[![skills.sh installs](https://skills.sh/b/jgoetzmann/polish-website)](https://skills.sh/jgoetzmann/polish-website)

An agent skill that audits and fixes an AI-built website or app before launch.
It covers security, legal compliance, AI-looking design and copy, and App Store
and Google Play readiness. Two scripts gather evidence first. Read-only agents
confirm it, a blind "stranger" and a black-box attacker check what is actually
deployed, and every fix comes with the command that proves it worked. Because
it's Markdown and stdlib Python, it works with any agent that supports skills.

## How it works

Coding agents optimize for "it works," not "it's safe." A vibecoded app usually
runs. It can also serve its whole database to anyone holding the public key,
ship a service-role key in the bundle, load a tracker before the cookie banner,
and look like every other template. The owner tends to find out last.

A checklist alone doesn't fix that. An agent handed a checklist reads it, greps
for a few items, and reports "✅ RLS enabled." So this skill runs on two ideas.

**Evidence before opinion.** Every finding carries the line or command output
that proves it, and the command that proves it's fixed. The scripts run first,
so the mechanical checks happen the same way every time. Every script finding
has to come back from an auditor confirmed or dismissed. Triage drops any
finding without evidence.

**Blind reviewers see what the public sees.** A reviewer who has read the code
knows what the app means to do. Attackers, regulators, store reviewers, and
visitors only see what it does. So the stranger never sees the repo, and the
attacker gets a URL and two test accounts.

## The phases

| Phase | What | Agents |
|---|---|---|
| 0 | Map the app and its triggers | none |
| 1 | Scan: scripts, then stack tools | none |
| 2 | Audit, read-only, in parallel | 3–6 |
| 3 | Triage and report; the user approves fixes | none |
| 4 | Fix by file ownership, in waves | 1/cluster |
| 5 | Verify: rerun, attack, fresh stranger | 2 |
| 6 | Handoff checklist | none |

Phases 0, 1, 3 and 6 are the orchestrator's. Nothing changes in the code before
the user has seen the P0 and P1 list.

## What it checks

The two scripts run 84 checks (68 static, 16 live), listed in
[docs/RULES.md](docs/RULES.md). The agent prompts cover what regex can't reach.

- **Security:** keys behind public env prefixes, secrets in bundles and git
  history, RLS missing or `using (true)`, views and `security definer` functions
  that bypass RLS, users writing their own `credits` or `role`, public buckets,
  Firebase test-mode rules, unverified Stripe webhooks, SQL built from strings,
  XSS sinks, open CORS, exposed `.env` and `.git`, source maps, missing headers,
  and what the anon key can actually read on the live project.
- **Legal:** remote Google Fonts, trackers and session replay without consent,
  missing policy pages, pre-checked consent boxes, and account deletion. Also
  accessibility markup, unsubscribe links, renewal terms, report buttons for
  user content, AI labeling, and unverifiable social proof.
- **AI tells:** the default stack appearing together without intent. That means
  purple-blue gradients, gradient text, glass cards, icon overload, Inter,
  emoji as icons, scroll-fade on everything, em-dash and buzzword density,
  placeholder people, and scaffold titles like "Vite + React."
- **Stores:** Capacitor `server.url` webview wrappers, in-app account deletion,
  Sign in with Apple parity, store billing and restore, the Android target SDK
  floor, sensitive permissions, iOS privacy manifests, and usage strings.

## Usage

```
/polish-website

Next.js + Supabase app, launching Friday. Prod is https://example.app,
staging is https://staging.example.app. Selling subscriptions in the US and EU.
```

Or in plain language:

```
Is my Lovable app safe to launch?
Make this site look less AI-generated.
Will Apple reject this Capacitor app?
```

A request about one area runs that area plus the secrets checks, which are
cheap and are where the P0s live.

The scripts also work on their own, with no agent:

```bash
python3 scripts/scan.py path/to/app                 # static repo scan
python3 scripts/probe.py https://staging.example.app # live probe
python3 scripts/probe.py https://staging.example.app --anon-read --only W14  # your own Supabase project only
python3 scripts/scan.py . --fail-on P1              # CI gate: exit 1 on any P0 or P1
```

To accept a finding on purpose, add a comment with the rule ID and a reason on
or above the line. For a whole file, use the `-file` form. For repo-level
findings, add a line to `.polish-website-ignore`:

```
<!-- polish-website-ignore D12 tagline approved by the brand team -->
// polish-website-ignore-file S02 fixtures use fake keys
```

In `.polish-website-ignore`, each line is `<ID[,ID]> <path glob> <reason>`:

```
D06 * Inter is the brand typeface
```

A suppression with no reason is ignored. Every applied one is listed in the
report's notes, so accepting a finding stays visible.

### Without subagents

The audit still works. Run the scripts, then work through each auditor prompt
yourself as a checklist. You lose the blindness: the stranger can't be blind if
you've read the code, and the attack pass becomes a self-review. Show the site
to one real person instead, and treat your own attack pass as weaker evidence.

## When not to use it

- Against anything you don't own. The live checks and the attack pass run only
  against targets the owner confirms, staging first.
- As the only review of a system that moves money, holds health records, or has
  a team. Run it, then get a professional pentest and a lawyer.
- As legal advice. It is a starting point that tells you what to ask a lawyer.

## What it looks like from outside

Phase 1 prints a few dozen findings. Most are P3 design tells, plus a handful of
P0s and P1s that matter. If a live key turns up, you hear about it right away,
not in the report. Phase 3 is a single message: the P0 and P1 list and the fix
plan. After you approve, fixes land in commits per wave. The last message lists
what changed, what's still open for you (rotations, dashboards, store forms, a
lawyer), and what was skipped and why.

## What's in here

```
SKILL.md                      the skill itself
README.md                     this file
AGENTS.md                     repo conventions for agents working on this package
LICENSE                       MIT
.polish-website-ignore          accepted findings: the scanner's own patterns in scripts/
agents/
  security-auditor.md         Phase 2: secrets, data, auth, abuse, ops
  legal-auditor.md            Phase 2: pages, consent, accessibility, feature-triggered law
  design-auditor.md           Phase 2: AI tells, copy, SEO basics
  store-auditor.md            Phase 2: App Store and Google Play
  stranger.md                 Phase 2 and 5: the deployed site, blind
  fixer.md                    Phase 4: fix one file cluster, verify each fix
  attacker.md                 Phase 5: black-box A1–A10 against staging
  openai.yaml                 agent interface manifest
scripts/
  scan.py                     static repo scan
  probe.py                    live URL probe
  _common.py                  finding shape, redaction, secret patterns
  test_scan.py, test_probe.py every rule seen firing, plus clean fixtures
  selftest.py                 runs both test suites
  validate-package.py         package validator CI runs on every push
docs/
  RULES.md                    every check, generated from the scripts
  BUILD-POLISH-WEBSITE.md       design rationale
  SOURCES.md                  where each dated claim came from
.claude-plugin/               plugin and marketplace manifests
.github/workflows/            validate, release, link check
web/index.html                landing page
vercel.json                   deploy config for the landing page
```

## Version history

<details><summary>Show release notes</summary>

- **1.0.0** — First release. Turns the single-file checklist into a
  seven-phase audit with two evidence scripts, seven agent roles, a fixed
  finding shape, and a launch gate. Dated legal and store rules were
  fact-checked on 2026-09-29.

</details>

## License

MIT

## Installation

With the Skills CLI:

```bash
npx skills add jgoetzmann/polish-website --global
```

Leave off `--global` to install into the current project only. Add
`--agent <name>` or `--agent '*'` to choose which agents receive it, then
reload their skills.

Claude Code 2.1.142 or newer can install it as a plugin:

```text
/plugin marketplace add jgoetzmann/polish-website
/plugin install polish-website@polish-website
```

The plugin command is `/polish-website:polish-website`.

For a manual install, copy `SKILL.md`, `agents/`, and `scripts/` into the
agent's skill folder. The agent prompts and the scripts are required, not
optional.
