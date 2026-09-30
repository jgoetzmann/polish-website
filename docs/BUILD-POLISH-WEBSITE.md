# BUILD-POLISH-WEBSITE.md

Why the skill is shaped the way it is. You don't need this file to use the
skill. You need it before you change a mechanic, because most of the rules look
arbitrary until you know which failure each one prevents.

## 1. Where it came from

Version 0 was a single Markdown checklist. It was distilled from 20 Instagram
reels on vibecoding risk (April to September 2026), with gaps filled for Google
Play. It had the right content and no mechanics. An agent handed a checklist
does what agents do with checklists: it reads the list, greps for a few items,
writes "✅ RLS enabled," and moves on. This package keeps that content and adds
the parts that make it run the same way every time.

## 2. The failures it is built against

1. **Checklist theater.** An agent reports an item as checked when it only read
   the item. **Countermeasure:** every finding carries `Evidence` and `Verify`,
   and triage drops a finding that lacks either one. The scripts run first, and
   every script finding must come back confirmed or dismissed. Silence is
   visible, because the IDs get diffed.
2. **The switch is on, the door is open.** RLS is enabled, but a policy says
   `using (true)`. Or a view without `security_invoker` reads the table anyway,
   or a public `security definer` function does. Or the update policy is right
   about rows and says nothing about columns, so a user sets their own
   `credits`. **Countermeasure:** S08 through S14 check each of these
   separately. The security auditor must answer four questions per table: who
   reads, who writes, which columns, how often. W14 then asks the deployed
   project directly what the anon key can read.
3. **The reviewer knows too much.** A reviewer who has read the code sees the
   intended design, not the rendered one. The same goes for access control: a
   white-box reviewer believes the middleware. **Countermeasure:** two blind
   roles. The stranger never sees the repo. The attacker gets a URL and two test
   accounts. The stranger reruns in a fresh agent after fixes, because an agent
   that saw the "before" is no longer blind.
4. **A scanner that cries wolf.** A rule that flags honest code teaches people
   to skim, and a skimmed report hides the real P0. **Countermeasure:** each
   script has a clean fixture that must produce zero findings. Anon keys,
   publishable keys, `next/font/google`, JSON-LD in `dangerouslySetInnerHTML`,
   tagged `sql` templates, and `alt=""` are all named traps with negative tests.
5. **Fixing the symptom.** Hiding the admin button, adding a client-side check,
   deleting the leaked key from the file. **Countermeasure:** the fixer's rule 4,
   "fix it where it's enforced," and rule 9, a leaked key is a `HUMAN` rotation.
   The failure-mode table in `SKILL.md` names the tell: the same finding comes
   back after a wave.
6. **The plausible fake.** Asked to remove placeholder testimonials, a model
   writes better testimonials. That turns a design problem into a false claim
   under the FTC's fake-review rule. **Countermeasure:** D13 and D14 are
   `HUMAN`, and the fixer's rule 6 says to delete or mark a slot, never replace.
7. **The audit turns into a rewrite.** A launch-week audit that refactors breaks
   working features. **Countermeasure:** fixers own disjoint file lists, fix
   only their finding IDs, and add no dependency the finding didn't name.
   Design changes that alter the look need the owner's yes.

## 3. Why these phases

- **Map before scan.** Most legal duties are triggered by a feature: accounts
  trigger COPPA age questions, subscriptions trigger auto-renewal law, uploads
  trigger DMCA and the TAKE IT DOWN Act. `MAP.md` has fixed keys, so skipped
  blocks are visible rather than forgotten.
- **Scripts before agents.** Regex is cheap, deterministic, and unimpressed by
  intent. Agents are good at the parts regex can't reach, like following a
  helper to see which role runs a query. So the scripts produce leads and the
  agents close them.
- **Read-only audit, then a gate, then fixes.** Auditors who fix as they go
  can't be checked, and the user never sees the whole picture before code
  changes. Phase 3 is the one place the user decides.
- **File ownership for fixers.** This is the one coordination mechanism, the
  same one fullsend uses: every file belongs to one agent per wave.
- **Verify three ways.** Rerunning the scripts proves the pattern is gone. The
  attack pass proves the behavior is gone. The fresh stranger proves the
  impression is gone. Each catches something the other two miss.

## 4. What the scripts deliberately don't do

- `scan.py` never touches the network. `probe.py` never sends anything but GET
  and HEAD, never leaves the target origin except for the Supabase project
  under `--anon-read`, and never prints a value it reads.
- Neither script tries to be a full SAST tool, secret scanner, or pentest.
  `SKILL.md` routes to gitleaks, trufflehog, the package manager's audit, the
  Supabase advisors, and Strix for depth. The scripts cover the failures that
  are common in AI-built apps and cheap to detect.

## 5. Figures and dates

Penalty figures come from the statutes, from regulators' inflation
adjustments, or from reported awards. They set priority. They are not
predictions of what any one app would owe. Every dated rule (store API levels,
application dates) was checked on 2026-09-29 and is logged in
[SOURCES.md](SOURCES.md). Store and platform rules move every year, so anything
in the prompts marked "confirm" is a standing instruction to check again.
