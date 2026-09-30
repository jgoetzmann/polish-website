# Rules

Every check the two scripts run. Generated from the scripts, so don't edit it
by hand. Regenerate it with `python3 scripts/validate-package.py --write-rules`.

Severity and owner are the defaults. A rule can report higher or lower when
the evidence says so. For example, S06 is P0 in a `'use client'` file and P1
otherwise.

## scan.py — static repo scan

| ID | Severity | Area | Owner | Check |
|---|---|---|---|---|
| S01 | P0 | secrets | AGENT | Secret-looking name behind a public env prefix |
| S02 | P0 | secrets | HUMAN | Hardcoded secret in a source file |
| S03 | P0 | secrets | HUMAN | .env file tracked by git |
| S04 | P0 | secrets | HUMAN | Secret in git history |
| S05 | P1 | secrets | AGENT | .env not covered by .gitignore |
| S06 | P0 | secrets | AGENT | Supabase service-role key in client code |
| S07 | P0 | secrets | AGENT | AI SDK running in the browser |
| S08 | P0 | data | AGENT | Public table without row level security |
| S09 | P1 | data | AGENT | RLS policy that allows everything |
| S10 | P1 | data | AGENT | Security definer function callable over RPC |
| S11 | P1 | data | AGENT | View without security_invoker |
| S12 | P1 | data | AGENT | Public storage bucket |
| S13 | P0 | data | AGENT | Firebase rules open to everyone |
| S14 | P1 | data | AGENT | Client writes its own plan, credits or role |
| S15 | P1 | auth | AGENT | Auth token stored in web storage |
| S16 | P1 | abuse | AGENT | Raw HTML sink (XSS risk) |
| S17 | P0 | abuse | AGENT | Stripe webhook without signature check |
| S18 | P1 | abuse | AGENT | SQL built by string interpolation |
| S19 | P1 | ops | AGENT | CORS open to any origin |
| S20 | P1 | ops | AGENT | Debug mode or public source maps in production |
| S21 | P1 | auth | AGENT | Password hashed with a fast hash |
| S22 | P2 | abuse | AGENT | Server routes without rate limiting |
| S23 | P2 | abuse | AGENT | Signup without bot protection |
| S24 | P2 | auth | AGENT | Open redirect from a query parameter |
| L01 | P1 | legal | AGENT | Google Fonts loaded from Google's servers |
| L02 | P1 | legal | AGENT | Tracker without a consent tool |
| L03 | P1 | legal | AGENT | Session replay recording |
| L04 | P1 | legal | HUMAN | Legal page missing |
| L05 | P1 | legal | AGENT | Pre-checked consent box |
| L06 | P2 | legal | HUMAN | Signup without an age check |
| L07 | P2 | legal | AGENT | AI features need disclosure and spend caps |
| L08 | P1 | legal | AGENT | Signup without account deletion |
| L09 | P1 | legal | AGENT | Image without alt text |
| L10 | P2 | legal | AGENT | Focus outline removed |
| L11 | P2 | legal | AGENT | Root html element without lang |
| L12 | P1 | legal | HUMAN | Email sending without unsubscribe |
| L13 | P1 | legal | AGENT | Subscription without renewal terms |
| L14 | P1 | legal | AGENT | User content without a report action |
| D01 | P3 | design | AGENT | Purple/blue gradient |
| D02 | P3 | design | AGENT | Gradient text |
| D03 | P3 | design | AGENT | Glassmorphism everywhere |
| D04 | P3 | design | AGENT | Colored left-border cards |
| D05 | P3 | design | AGENT | 20+ distinct lucide icons |
| D06 | P3 | design | AGENT | Inter as the typeface |
| D07 | P3 | copy | AGENT | Emoji in user-facing copy |
| D08 | P3 | design | AGENT | Scroll-reveal animation everywhere |
| D09 | P3 | design | AGENT | Grid, dot or noise filler texture |
| D10 | P3 | design | AGENT | Custom cursor or spotlight effect |
| D11 | P3 | copy | AGENT | Em dashes in user-facing copy |
| D12 | P3 | copy | AGENT | Marketing buzzwords |
| D13 | P1 | copy | HUMAN | Placeholder content |
| D14 | P1 | legal | HUMAN | Unverifiable social proof |
| D15 | P2 | seo | AGENT | Default scaffold title or assets |
| D16 | P2 | seo | AGENT | Missing robots, sitemap, 404, OG image or favicon |
| D17 | P2 | seo | AGENT | More than one h1 in a file |
| D18 | P3 | seo | HUMAN | AI crawlers blocked in robots.txt |
| D19 | P3 | design | AGENT | Untouched shadcn/ui theme |
| M01 | P0 | store | AGENT | Capacitor server.url left in config |
| M02 | P1 | store | HUMAN | Webview wrapper with little native value |
| M03 | P0 | store | AGENT | Native signup without in-app deletion |
| M04 | P1 | store | AGENT | Third-party login without Sign in with Apple |
| M05 | P1 | store | HUMAN | Web checkout in a native app, no IAP |
| M06 | P1 | store | AGENT | In-app purchases without restore |
| M07 | P0 | store | AGENT | Android targetSdk below the Play floor |
| M08 | P1 | store | AGENT | Sensitive Android permission |
| M09 | P1 | store | AGENT | iOS privacy manifest missing |
| M10 | P2 | store | AGENT | Vague iOS permission prompt |
| M11 | P3 | store | HUMAN | iPad supported: layout gets reviewed |

## probe.py — live URL probe

| ID | Severity | Area | Owner | Check |
|---|---|---|---|---|
| W01 | P0 | secrets | HUMAN | Secret in served HTML, JS or CSS |
| W02 | P1 | ops | AGENT | Source maps are publicly served |
| W03 | P0 | secrets | HUMAN | Exposed .env, .git, backup or SQL dump |
| W04 | P1 | ops | AGENT | No http to https redirect, or no https |
| W05 | P2 | ops | AGENT | Missing security header |
| W06 | P3 | ops | AGENT | Server or framework version disclosed |
| W07 | P1 | ops | AGENT | CORS reflects any origin |
| W08 | P2 | seo | AGENT | Missing or default page metadata |
| W09 | P2 | seo | AGENT | Client-rendered empty shell |
| W10 | P2 | seo | AGENT | robots.txt, sitemap.xml or llms.txt problem |
| W11 | P2 | seo | AGENT | Soft 404 or framework default 404 page |
| W12 | P1 | legal | AGENT | Google Fonts loaded from Google's servers |
| W13 | P1 | legal | AGENT | Tracker or session replay with no consent tool |
| W14 | P0 | data | HUMAN | Supabase data readable with the anon key |
| W15 | P2 | ops | AGENT | Mixed content on an https page |
| W16 | P1 | ops | AGENT | Directory listing enabled |
