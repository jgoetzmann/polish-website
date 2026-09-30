"""Tests for scan.py. Run from the package root:

    python3 -m unittest discover -s scripts -p 'test_scan.py' -v

Every rule has a positive test named test_<ID>_..., negatives cover the traps in the
spec's Notes column, and the clean fixtures (web, Capacitor, Expo) must produce zero findings.
Secrets are assembled from pieces so this file never contains a live-looking key.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import scan  # noqa: E402

SCAN = str(HERE / "scan.py")

STRIPE_LIVE = "sk_" + "live_" + "51Hq8ZrT9mKq2VbN7cXp3LwD"
OPENAI_KEY = "sk-" + "proj-" + "Qm3Tn8Vb2Lk9Zr4Wx7Hs1Jd6Fg5Pa0Ce"


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def make_jwt(role: str) -> str:
    return ".".join((_b64({"alg": "HS256", "typ": "JWT"}), _b64({"iss": "supabase", "role": role}), "Zx8Qw2Er4Ty6Ui8Op0As"))


SERVICE_JWT = make_jwt("service_role")
ANON_JWT = make_jwt("anon")
PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 32

HAS_GIT = shutil.which("git") is not None
GIT_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t.invalid"}


def write_tree(root: Path, files: dict) -> None:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=GIT_ENV)


def git_commit_all(root: Path, message: str = "commit", force: tuple = ()) -> None:
    git(root, "add", "-A")
    for rel in force:
        git(root, "add", "-f", rel)
    git(root, "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", message)


def scan_tree(files: dict, only: str | None = None, git_repo: bool = False):
    """Write files into a temp dir, scan it, return (findings, notes)."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_tree(root, files)
        if git_repo:
            git(root, "init", "-q")
            git_commit_all(root)
        return scan.run(root, ".", scan.select_rules(only))


def merged(*trees: dict) -> dict:
    out: dict = {}
    for t in trees:
        out.update(t)
    return out


def describe(findings) -> list[str]:
    return [f"{f.id} {f.severity} {f.where} | {f.evidence}" for f in findings]


class ScanTestCase(unittest.TestCase):
    def fires(self, rule_id: str, files: dict, git_repo: bool = False) -> list:
        findings, _ = scan_tree(files, rule_id, git_repo)
        hits = [f for f in findings if f.id == rule_id]
        self.assertTrue(hits, f"{rule_id} did not fire")
        return hits

    def quiet(self, rule_id: str, files: dict, git_repo: bool = False) -> None:
        findings, _ = scan_tree(files, rule_id, git_repo)
        self.assertEqual([], describe(findings))


# --- Clean fixture: a small Next.js App Router + Supabase app that does everything right ---

CLEAN_APP = {
    "package.json": json.dumps({
        "name": "tidepool",
        "private": True,
        "scripts": {"dev": "next dev", "build": "next build"},
        "dependencies": {
            "next": "15.5.0", "react": "19.1.0", "react-dom": "19.1.0",
            "@supabase/ssr": "^0.7.0", "@supabase/supabase-js": "^2.57.0",
            "stripe": "^18.5.0", "@upstash/ratelimit": "^2.0.6", "@upstash/redis": "^1.35.0",
            "@marsidev/react-turnstile": "^1.3.0", "resend": "^6.0.0", "@vercel/analytics": "^1.5.0",
            "server-only": "^0.0.1",
        },
        "devDependencies": {"typescript": "^5.9.0", "tailwindcss": "^4.1.0", "@types/react": "^19.1.0"},
    }, indent=2),
    ".gitignore": "node_modules/\n.next/\n.env*\n!.env.example\n",
    ".env.example": (
        "NEXT_PUBLIC_SUPABASE_URL=\nNEXT_PUBLIC_SUPABASE_ANON_KEY=\nNEXT_PUBLIC_TURNSTILE_SITE_KEY=\n"
        "NEXT_PUBLIC_SITE_URL=http://localhost:3000\nSUPABASE_SERVICE_ROLE_KEY=\nSTRIPE_SECRET_KEY=\n"
        "STRIPE_WEBHOOK_SECRET=\nSTRIPE_PRICE_PLUS=\nRESEND_API_KEY=\nUPSTASH_REDIS_REST_URL=\nUPSTASH_REDIS_REST_TOKEN=\n"
    ),
    "README.md": "# Tidepool\n\nStarted from the Acme starter. Lorem ipsum notes live in docs.\n",
    "next.config.ts": """import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  poweredByHeader: false,
  images: { remotePatterns: [{ protocol: 'https', hostname: '*.supabase.co' }] },
}

export default nextConfig
""",
    "app/layout.tsx": """import type { Metadata } from 'next'
import { IBM_Plex_Sans } from 'next/font/google'
import { Analytics } from '@vercel/analytics/react'
import Footer from '@/components/Footer'
import './globals.css'

const plex = IBM_Plex_Sans({ subsets: ['latin'], weight: ['400', '600'] })

export const metadata: Metadata = {
  title: 'Tidepool',
  description: 'Field notes from tide pools, shared by the people who find them.',
  openGraph: { title: 'Tidepool', images: ['/opengraph-image.png'] },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className={plex.className}>
        {children}
        <Footer />
        <Analytics />
      </body>
    </html>
  )
}
""",
    "app/globals.css": """@import "tailwindcss";

:root {
  --background: #fdfcf8;
  --foreground: #1f2933;
  --accent: #0f766e;
}

body {
  background: var(--background);
  color: var(--foreground);
}

a:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}
""",
    "app/page.tsx": """import Link from 'next/link'
import Image from 'next/image'

export default function Home() {
  return (
    <main className="mx-auto max-w-2xl px-6 py-16">
      <h1 className="text-4xl font-semibold text-slate-900">Tide pool notes from the Oregon coast</h1>
      <p className="mt-4 text-lg text-slate-700">
        Log what you saw at low tide, add a photo, and read what other visitors found at the same spot.
      </p>
      <Image src="/pools/haystack.jpg" alt="Anemones in a pool at Haystack Rock" width={800} height={533} />
      <Image
        src="/divider.svg"
        width={800}
        height={8}
        alt=""
      />
      <Link href="/signup" className="mt-8 inline-block rounded bg-teal-700 px-4 py-2 text-white focus-visible:ring-2">
        Start a log
      </Link>
    </main>
  )
}
""",
    "app/not-found.tsx": """import Link from 'next/link'

export default function NotFound() {
  return (
    <main className="mx-auto max-w-2xl px-6 py-16">
      <h1 className="text-2xl font-semibold">That page washed out</h1>
      <p className="mt-2">The link may be old. <Link href="/">Go to the home page</Link>.</p>
    </main>
  )
}
""",
    "app/robots.ts": """import type { MetadataRoute } from 'next'

export default function robots(): MetadataRoute.Robots {
  return {
    rules: { userAgent: '*', allow: '/', disallow: '/settings' },
    sitemap: 'https://tidepool.app/sitemap.xml',
  }
}
""",
    "app/sitemap.ts": """import type { MetadataRoute } from 'next'

export default function sitemap(): MetadataRoute.Sitemap {
  const base = 'https://tidepool.app'
  return ['', '/pricing', '/privacy', '/terms', '/accessibility', '/refunds'].map((path) => ({
    url: `${base}${path}`,
    lastModified: new Date('2026-09-01'),
  }))
}
""",
    "app/icon.png": PNG,
    "app/opengraph-image.png": PNG,
    "app/privacy/page.tsx": """export const metadata = { title: 'Privacy policy' }

export default function Privacy() {
  return (
    <main className="prose mx-auto px-6 py-16">
      <h1>Privacy policy</h1>
      <p>We store your email address, your profile and the notes you post. Vercel Analytics counts visits without cookies.</p>
      <p>Stripe handles payments, so we never see your card number.</p>
      <p>Email privacy@tidepool.app to get a copy of your data or to have it deleted.</p>
    </main>
  )
}
""",
    "app/terms/page.tsx": """export const metadata = { title: 'Terms of service' }

export default function Terms() {
  return (
    <main className="prose mx-auto px-6 py-16">
      <h1>Terms of service</h1>
      <p>You must be at least 13 years old to use Tidepool.</p>
      <p>Plus renews every month until you cancel it in Settings.</p>
      <p>Post only what you saw yourself. We remove notes that harass people or disclose private locations.</p>
    </main>
  )
}
""",
    "app/accessibility/page.tsx": """export default function Accessibility() {
  return (
    <main className="prose mx-auto px-6 py-16">
      <h1>Accessibility</h1>
      <p>We aim for WCAG 2.2 AA. If something is hard to use, write to access@tidepool.app and we will fix it.</p>
    </main>
  )
}
""",
    "app/refunds/page.tsx": """export default function Refunds() {
  return (
    <main className="prose mx-auto px-6 py-16">
      <h1>Refunds</h1>
      <p>Ask within 14 days of a charge and we refund it in full.</p>
    </main>
  )
}
""",
    "app/pricing/page.tsx": """import Link from 'next/link'

export default function Pricing() {
  return (
    <main className="mx-auto max-w-2xl px-6 py-16">
      <h1 className="text-3xl font-semibold">Pricing</h1>
      <section className="mt-8 rounded border border-slate-200 p-6">
        <h2 className="text-xl font-semibold">Plus</h2>
        <p className="mt-2">$4 per month. Renews monthly until you cancel in Settings.</p>
        <p className="mt-1 text-sm text-slate-600">Unlimited photo uploads and offline tide tables.</p>
        <form action="/api/checkout" method="post">
          <button className="mt-4 rounded bg-teal-700 px-4 py-2 text-white focus-visible:ring-2">Subscribe</button>
        </form>
      </section>
      <p className="mt-6 text-sm">See the <Link href="/refunds">refund policy</Link>.</p>
    </main>
  )
}
""",
    "app/signup/page.tsx": """'use client'

import { useState } from 'react'
import { Turnstile } from '@marsidev/react-turnstile'
import { createClient } from '@/lib/supabase/client'

export default function SignUp() {
  const [captchaToken, setCaptchaToken] = useState('')
  const [newsletter, setNewsletter] = useState(false)
  const [message, setMessage] = useState('')

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const supabase = createClient()
    const { error } = await supabase.auth.signUp({
      email: String(form.get('email')),
      password: String(form.get('password')),
      options: { captchaToken, data: { full_name: String(form.get('name')), newsletter } },
    })
    setMessage(error ? error.message : 'Check your inbox to confirm your address.')
  }

  return (
    <main className="mx-auto max-w-md px-6 py-16">
      <h1 className="text-2xl font-semibold">Create your account</h1>
      <form onSubmit={onSubmit} className="mt-6 space-y-4">
        <label className="block">
          Full name
          <input name="name" placeholder="Jane Doe" className="mt-1 w-full rounded border px-3 py-2" />
        </label>
        <label className="block">
          Email
          <input name="email" type="email" required placeholder="you@example.com" className="mt-1 w-full rounded border px-3 py-2" />
        </label>
        <label className="block">
          Password
          <input name="password" type="password" required minLength={10} className="mt-1 w-full rounded border px-3 py-2" />
        </label>
        <label className="flex gap-2">
          <input type="checkbox" name="age" required />
          I am at least 13 years old.
        </label>
        <label className="flex gap-2">
          <input type="checkbox" name="newsletter" checked={newsletter} onChange={(e) => setNewsletter(e.target.checked)} />
          Send me the monthly tide calendar.
        </label>
        <Turnstile siteKey={process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY!} onSuccess={setCaptchaToken} />
        <button className="w-full rounded bg-teal-700 px-4 py-2 text-white">Create account</button>
      </form>
      {message && <p className="mt-4">{message}</p>}
    </main>
  )
}
""",
    "app/signup/page.test.tsx": """import { render } from '@testing-library/react'

it('renders', () => {
  document.body.innerHTML = '<div id="root"></div>'
  render(<img src="/x.png" />)
})
""",
    "app/settings/page.tsx": """'use client'

import { useEffect, useState } from 'react'
import ProfileForm from '@/components/ProfileForm'

export default function Settings() {
  const [theme, setTheme] = useState('light')
  const [status, setStatus] = useState('')

  useEffect(() => {
    localStorage.setItem('theme', theme)
    document.documentElement.dataset.theme = theme
  }, [theme])

  async function deleteAccount() {
    if (!confirm('Delete your account and every note you posted? This cannot be undone.')) return
    const res = await fetch('/api/account', { method: 'DELETE' })
    setStatus(res.ok ? 'Your account was deleted.' : 'Something went wrong. Please try again.')
  }

  return (
    <main className="mx-auto max-w-md px-6 py-16">
      <h1 className="text-2xl font-semibold">Settings</h1>
      <ProfileForm />
      <label className="mt-6 block">
        Theme
        <select value={theme} onChange={(e) => setTheme(e.target.value)} className="ml-2 rounded border">
          <option value="light">Light</option>
          <option value="dark">Dark</option>
        </select>
      </label>
      <button onClick={deleteAccount} className="mt-10 rounded border border-red-700 px-4 py-2 text-red-700">
        Delete account
      </button>
      {status && <p className="mt-4">{status}</p>}
    </main>
  )
}
""",
    "app/posts/[id]/page.tsx": """import Image from 'next/image'
import { notFound } from 'next/navigation'
import { createClient } from '@/lib/supabase/server'
import ReportButton from '@/components/ReportButton'

export default async function PostPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  const supabase = await createClient()
  const { data: post } = await supabase.from('posts').select('id, title, body, photo_url, comments(id, body)').eq('id', id).single()
  if (!post) notFound()

  const jsonLd = { '@context': 'https://schema.org', '@type': 'Article', headline: post.title }

  return (
    <main className="mx-auto max-w-2xl px-6 py-16">
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
      <h1 className="text-3xl font-semibold">{post.title}</h1>
      {post.photo_url && <Image src={post.photo_url} alt={post.title} width={800} height={533} />}
      <p className="mt-4 whitespace-pre-line">{post.body}</p>
      <h2 className="mt-10 text-xl font-semibold">Comments</h2>
      <ul className="mt-4 space-y-4">
        {post.comments.map((comment: { id: string; body: string }) => (
          <li key={comment.id} className="border-b border-slate-200 pb-3">
            <p>{comment.body}</p>
            <ReportButton commentId={comment.id} />
          </li>
        ))}
      </ul>
    </main>
  )
}
""",
    "app/auth/callback/route.ts": """import { NextResponse } from 'next/server'
import { createClient } from '@/lib/supabase/server'

export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url)
  const code = searchParams.get('code')
  let next = searchParams.get('next') ?? '/'
  if (!next.startsWith('/') || next.startsWith('//')) next = '/'

  if (code) {
    const supabase = await createClient()
    const { error } = await supabase.auth.exchangeCodeForSession(code)
    if (!error) return NextResponse.redirect(`${origin}${next}`)
  }
  return NextResponse.redirect(`${origin}/auth/error`)
}
""",
    "app/api/checkout/route.ts": """import Stripe from 'stripe'
import { NextResponse } from 'next/server'
import { createClient } from '@/lib/supabase/server'
import { ratelimit } from '@/lib/ratelimit'

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)

export async function POST() {
  const supabase = await createClient()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return NextResponse.json({ error: 'Sign in first' }, { status: 401 })
  const { success } = await ratelimit.limit(`checkout:${user.id}`)
  if (!success) return NextResponse.json({ error: 'Too many requests' }, { status: 429 })

  const session = await stripe.checkout.sessions.create({
    mode: 'subscription',
    line_items: [{ price: process.env.STRIPE_PRICE_PLUS!, quantity: 1 }],
    client_reference_id: user.id,
    success_url: `${process.env.NEXT_PUBLIC_SITE_URL}/settings?upgraded=1`,
    cancel_url: `${process.env.NEXT_PUBLIC_SITE_URL}/pricing`,
  })
  return NextResponse.redirect(session.url!, 303)
}
""",
    "app/api/webhooks/stripe/route.ts": """import Stripe from 'stripe'
import { admin } from '@/lib/supabase/admin'

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)

export async function POST(req: Request) {
  const body = await req.text()
  const signature = req.headers.get('stripe-signature')
  let event: Stripe.Event
  try {
    event = stripe.webhooks.constructEvent(body, signature!, process.env.STRIPE_WEBHOOK_SECRET!)
  } catch {
    return new Response('Invalid signature', { status: 400 })
  }
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object
    await admin.from('profiles').update({ plan: 'plus' }).eq('id', session.client_reference_id!)
  }
  return new Response('ok')
}
""",
    "app/api/account/route.ts": """import { NextResponse } from 'next/server'
import { createClient } from '@/lib/supabase/server'
import { admin } from '@/lib/supabase/admin'

export async function DELETE() {
  const supabase = await createClient()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return NextResponse.json({ error: 'Sign in first' }, { status: 401 })
  await admin.from('comments').delete().eq('author_id', user.id)
  await admin.auth.admin.deleteUser(user.id)
  return NextResponse.json({ deleted: true })
}
""",
    "app/api/comments/route.ts": """import { NextResponse } from 'next/server'
import { createClient } from '@/lib/supabase/server'
import { ratelimit } from '@/lib/ratelimit'

export async function POST(req: Request) {
  const supabase = await createClient()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return NextResponse.json({ error: 'Sign in first' }, { status: 401 })
  const { success } = await ratelimit.limit(`comment:${user.id}`)
  if (!success) return NextResponse.json({ error: 'Slow down a little' }, { status: 429 })
  const { postId, body } = await req.json()
  const { error } = await supabase.from('comments').insert({ post_id: postId, author_id: user.id, body })
  return NextResponse.json({ ok: !error })
}
""",
    "components/Footer.tsx": """import Link from 'next/link'

const links = [
  { href: '/privacy', label: 'Privacy' },
  { href: '/terms', label: 'Terms' },
  { href: '/accessibility', label: 'Accessibility' },
  { href: '/refunds', label: 'Refunds' },
]

export default function Footer() {
  return (
    <footer className="mt-16 border-t border-slate-200 px-6 py-8 text-sm text-slate-600">
      <nav className="flex gap-4">
        {links.map((link) => (
          <Link key={link.href} href={link.href} className="focus-visible:ring-2">
            {link.label}
          </Link>
        ))}
      </nav>
      <p className="mt-4">Tidepool, 1200 NW Front Ave, Portland, OR 97209</p>
    </footer>
  )
}
""",
    "components/ProfileForm.tsx": """'use client'

import { useState } from 'react'
import { createClient } from '@/lib/supabase/client'

export default function ProfileForm() {
  const [saved, setSaved] = useState(false)

  async function save(form: FormData) {
    const supabase = createClient()
    const { data: { user } } = await supabase.auth.getUser()
    if (!user) return
    await supabase
      .from('profiles')
      .update({ display_name: String(form.get('display_name')), bio: String(form.get('bio')) })
      .eq('id', user.id)
    setSaved(true)
  }

  return (
    <form action={save} className="mt-6 space-y-3">
      <label className="block">
        Display name
        <input name="display_name" className="mt-1 w-full rounded border px-3 py-2" />
      </label>
      <label className="block">
        Bio
        <textarea name="bio" rows={3} className="mt-1 w-full rounded border px-3 py-2" />
      </label>
      <button className="rounded bg-teal-700 px-4 py-2 text-white">Save</button>
      {saved && <p>Saved.</p>}
    </form>
  )
}
""",
    "components/ReportButton.tsx": """'use client'

import { useState } from 'react'
import { createClient } from '@/lib/supabase/client'

export default function ReportButton({ commentId }: { commentId: string }) {
  const [sent, setSent] = useState(false)

  async function report() {
    const supabase = createClient()
    await supabase.from('reports').insert({ comment_id: commentId, reason: 'reported from the comment menu' })
    setSent(true)
  }

  return (
    <button onClick={report} disabled={sent} className="text-sm text-slate-600 underline">
      {sent ? 'Thanks, we will review it' : 'Report'}
    </button>
  )
}
""",
    "lib/supabase/client.ts": """import { createBrowserClient } from '@supabase/ssr'

export function createClient() {
  return createBrowserClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!)
}
""",
    "lib/supabase/server.ts": """import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'

export async function createClient() {
  const cookieStore = await cookies()
  return createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {
    cookies: {
      getAll: () => cookieStore.getAll(),
      setAll: (list) => list.forEach(({ name, value, options }) => cookieStore.set(name, value, options)),
    },
  })
}
""",
    "lib/supabase/admin.ts": """import 'server-only'
import { createClient } from '@supabase/supabase-js'

// Server-only client for account deletion and webhooks.
export const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!, {
  auth: { persistSession: false },
})
""",
    "lib/ratelimit.ts": """import { Ratelimit } from '@upstash/ratelimit'
import { Redis } from '@upstash/redis'

export const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(10, '1 m'),
})
""",
    "lib/email.ts": """import { Resend } from 'resend'
import WeeklyDigest from '@/emails/weekly-digest'

const resend = new Resend(process.env.RESEND_API_KEY)

export async function sendDigest(to: string, unsubscribeUrl: string) {
  return resend.emails.send({
    from: 'Tidepool <notes@tidepool.app>',
    to,
    subject: 'This week at low tide',
    react: WeeklyDigest({ unsubscribeUrl }),
    headers: { 'List-Unsubscribe': `<${unsubscribeUrl}>` },
  })
}
""",
    "emails/weekly-digest.tsx": """export default function WeeklyDigest({ unsubscribeUrl }: { unsubscribeUrl: string }) {
  return (
    <div style={{ fontFamily: 'Georgia, serif' }}>
      <p>Here are the pools with the lowest tides this week.</p>
      <p style={{ fontSize: 12 }}>
        Tidepool, 1200 NW Front Ave, Portland, OR 97209. <a href={unsubscribeUrl}>Unsubscribe</a>
      </p>
    </div>
  )
}
""",
    "content/posts/first-low-tide.md": "# First low tide of the season\n\nWe counted eleven ochre sea stars at the north end.\n",
    "supabase/config.toml": """[auth.captcha]
enabled = true
provider = "turnstile"

[storage.buckets.avatars]
public = false
file_size_limit = "5MiB"
""",
    "supabase/migrations/20260101000000_init.sql": """-- Tidepool schema. Every public table has RLS.
create schema if not exists private;

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  display_name text,
  bio text,
  birth_date date,
  plan text not null default 'free',
  created_at timestamptz not null default now()
);
alter table public.profiles enable row level security;
create policy "Owners read their profile" on public.profiles
  for select to authenticated using ((select auth.uid()) = id);
create policy "Owners update their profile" on public.profiles
  for update to authenticated using ((select auth.uid()) = id) with check ((select auth.uid()) = id);
revoke update (plan) on table public.profiles from authenticated;

create table if not exists public.posts (
  id uuid primary key default gen_random_uuid(),
  author_id uuid not null references public.profiles (id) on delete cascade,
  title text not null,
  body text not null,
  photo_url text,
  published boolean not null default false
);
alter table public.posts enable row level security;
create policy "Published posts are readable" on public.posts for select using (published);
create policy "Authors write their posts" on public.posts
  for insert to authenticated with check ((select auth.uid()) = author_id);

create table public.comments (
  id uuid primary key default gen_random_uuid(),
  post_id uuid not null references public.posts (id) on delete cascade,
  author_id uuid not null references public.profiles (id) on delete cascade,
  body text not null,
  hidden boolean not null default false
);
alter table public.comments enable row level security;
create policy "Visible comments are readable" on public.comments for select using (not hidden);
create policy "Members comment as themselves" on public.comments
  for insert to authenticated with check ((select auth.uid()) = author_id);

create table public.reports (
  id bigint generated always as identity primary key,
  comment_id uuid not null references public.comments (id) on delete cascade,
  reporter_id uuid not null default auth.uid(),
  reason text not null
);
alter table public.reports enable row level security;
create policy "Members file reports" on public.reports
  for insert to authenticated with check ((select auth.uid()) = reporter_id);

create table private.stripe_events (id text primary key, received_at timestamptz default now());

create view public.post_stats with (security_invoker = true) as
  select post_id, count(*) as comment_count from public.comments group by post_id;

create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id) values (new.id);
  return new;
end;
$$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute procedure public.handle_new_user();

create or replace function public.delete_my_comments() returns void
language sql security definer set search_path = '' as $$
  delete from public.comments where author_id = (select auth.uid());
$$;
revoke execute on function public.delete_my_comments() from public, anon;
grant execute on function public.delete_my_comments() to authenticated;

insert into storage.buckets (id, name, public) values ('avatars', 'avatars', false);
""",
}

# The same app shipped as a Capacitor app: real plugins, IAP with restore, privacy manifest.
CAPACITOR_EXTRA = {
    "package.json": json.dumps({
        **json.loads(CLEAN_APP["package.json"]),
        "dependencies": {
            **json.loads(CLEAN_APP["package.json"])["dependencies"],
            "@capacitor/core": "^7.4.0", "@capacitor/ios": "^7.4.0", "@capacitor/android": "^7.4.0",
            "@capacitor/push-notifications": "^7.0.0", "@capacitor/camera": "^7.0.0",
            "@revenuecat/purchases-capacitor": "^11.0.0",
        },
        "devDependencies": {**json.loads(CLEAN_APP["package.json"])["devDependencies"], "@capacitor/cli": "^7.4.0"},
    }, indent=2),
    "capacitor.config.ts": """import type { CapacitorConfig } from '@capacitor/cli'

const config: CapacitorConfig = {
  appId: 'app.tidepool',
  appName: 'Tidepool',
  webDir: 'out',
}

export default config
""",
    "components/RestorePurchases.tsx": """'use client'

import { Purchases } from '@revenuecat/purchases-capacitor'

export default function RestorePurchases() {
  return (
    <button onClick={() => Purchases.restorePurchases()} className="text-sm underline">
      Restore purchases
    </button>
  )
}
""",
    "ios/App/App.xcodeproj/project.pbxproj": """// !$*UTF8*$!
{
	objects = {
		504EC3171FED79650016851F /* Release */ = {
			buildSettings = {
				PRODUCT_BUNDLE_IDENTIFIER = app.tidepool;
				TARGETED_DEVICE_FAMILY = 1;
			};
		};
	};
}
""",
    "ios/App/App/PrivacyInfo.xcprivacy": """<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>NSPrivacyTracking</key><false/></dict></plist>
""",
    "ios/App/App/Info.plist": """<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>NSCameraUsageDescription</key>
	<string>Take a photo of a tide pool to attach it to your note.</string>
	<key>UIDeviceFamily</key>
	<array>
		<integer>1</integer>
	</array>
</dict>
</plist>
""",
    "android/app/build.gradle": """android {
    namespace "app.tidepool"
    defaultConfig {
        applicationId "app.tidepool"
        minSdkVersion rootProject.ext.minSdkVersion
        targetSdkVersion rootProject.ext.targetSdkVersion
    }
}
""",
    # One level above today's Play floor, so M07 stays quiet until the floor moves again.
    "android/variables.gradle": "ext {\n    minSdkVersion = 24\n    compileSdkVersion = 37\n    targetSdkVersion = 37\n}\n",
    "android/app/src/main/AndroidManifest.xml": """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" xmlns:tools="http://schemas.android.com/tools">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
    <uses-permission android:name="android.permission.READ_MEDIA_IMAGES" tools:node="remove" />
</manifest>
""",
}

# A store-first Expo app: Apple login beside Google, IAP with restore, deletion, privacy manifest.
EXPO_APP = {
    "package.json": json.dumps({
        "name": "tidepool-mobile",
        "main": "expo-router/entry",
        "dependencies": {
            "expo": "~54.0.0", "expo-router": "~6.0.0", "expo-apple-authentication": "~8.0.0",
            "expo-build-properties": "~1.0.0", "expo-image-picker": "~17.0.0", "react": "19.1.0",
            "react-native": "0.81.0", "react-native-purchases": "^9.2.0",
            "@hcaptcha/react-native-hcaptcha": "^1.9.0", "@supabase/supabase-js": "^2.57.0",
            "@react-native-async-storage/async-storage": "2.2.0",
        },
    }, indent=2),
    ".gitignore": "node_modules/\n.expo/\n.env*\n",
    "app.json": json.dumps({"expo": {
        "name": "Tidepool", "slug": "tidepool",
        "ios": {
            "bundleIdentifier": "app.tidepool", "supportsTablet": False,
            "infoPlist": {"NSPhotoLibraryUsageDescription": "Choose a photo of a tide pool to attach to your note."},
            "privacyManifests": {"NSPrivacyAccessedAPITypes": [{
                "NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategoryUserDefaults",
                "NSPrivacyAccessedAPITypeReasons": ["CA92.1"]}]},
        },
        "android": {"package": "app.tidepool", "permissions": ["android.permission.CAMERA"],
                    "blockedPermissions": ["android.permission.READ_MEDIA_IMAGES"]},
        "plugins": ["expo-router", "expo-apple-authentication",
                    ["expo-build-properties", {"android": {"targetSdkVersion": 37, "compileSdkVersion": 37}}]],
    }}, indent=2),
    "lib/supabase.ts": """import AsyncStorage from '@react-native-async-storage/async-storage'
import { createClient } from '@supabase/supabase-js'

export const supabase = createClient(process.env.EXPO_PUBLIC_SUPABASE_URL!, process.env.EXPO_PUBLIC_SUPABASE_ANON_KEY!, {
  auth: { storage: AsyncStorage, autoRefreshToken: true, persistSession: true, detectSessionInUrl: false },
})
""",
    "app/_layout.tsx": """import { Stack } from 'expo-router'

export default function RootLayout() {
  return <Stack />
}
""",
    "app/index.tsx": """import { Image, Text, View } from 'react-native'

export default function Home() {
  return (
    <View>
      <Image source={require('../assets/pool.jpg')} style={{ width: 320, height: 200 }} accessibilityLabel="Sea stars in a tide pool" />
      <Text>Log what you saw at low tide.</Text>
    </View>
  )
}
""",
    "app/(auth)/sign-up.tsx": """import { useRef, useState } from 'react'
import { Button, Switch, Text, TextInput, View } from 'react-native'
import ConfirmHcaptcha from '@hcaptcha/react-native-hcaptcha'
import { supabase } from '../../lib/supabase'

export default function SignUp() {
  const captcha = useRef<ConfirmHcaptcha>(null)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [oldEnough, setOldEnough] = useState(false)

  async function submit(captchaToken: string) {
    await supabase.auth.signUp({ email, password, options: { captchaToken } })
  }

  return (
    <View>
      <TextInput value={email} onChangeText={setEmail} autoComplete="email" accessibilityLabel="Email" />
      <TextInput value={password} onChangeText={setPassword} secureTextEntry accessibilityLabel="Password" />
      <View>
        <Switch value={oldEnough} onValueChange={setOldEnough} />
        <Text>I am 13 or older</Text>
      </View>
      <ConfirmHcaptcha ref={captcha} siteKey={process.env.EXPO_PUBLIC_HCAPTCHA_SITE_KEY!} onMessage={(e) => submit(e.nativeEvent.data)} />
      <Button title="Create account" disabled={!oldEnough} onPress={() => captcha.current?.show()} />
    </View>
  )
}
""",
    "app/(auth)/sign-in.tsx": """import * as AppleAuthentication from 'expo-apple-authentication'
import { Button, View } from 'react-native'
import { supabase } from '../../lib/supabase'

export default function SignIn() {
  async function withApple() {
    const credential = await AppleAuthentication.signInAsync({
      requestedScopes: [AppleAuthentication.AppleAuthenticationScope.EMAIL],
    })
    if (credential.identityToken) {
      await supabase.auth.signInWithIdToken({ provider: 'apple', token: credential.identityToken })
    }
  }

  async function withGoogle() {
    await supabase.auth.signInWithOAuth({ provider: 'google', options: { redirectTo: 'tidepool://auth' } })
  }

  return (
    <View>
      <AppleAuthentication.AppleAuthenticationButton
        buttonType={AppleAuthentication.AppleAuthenticationButtonType.SIGN_IN}
        buttonStyle={AppleAuthentication.AppleAuthenticationButtonStyle.BLACK}
        cornerRadius={6}
        style={{ height: 44 }}
        onPress={withApple}
      />
      <Button title="Continue with Google" onPress={withGoogle} />
    </View>
  )
}
""",
    "app/settings.tsx": """import { Alert, Button, Linking, View } from 'react-native'
import Purchases from 'react-native-purchases'
import { supabase } from '../lib/supabase'

export default function Settings() {
  async function deleteAccount() {
    const { data } = await supabase.auth.getSession()
    await fetch(`${process.env.EXPO_PUBLIC_API_URL}/account`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${data.session?.access_token}` },
    })
    await supabase.auth.signOut()
  }

  return (
    <View>
      <Button title="Restore purchases" onPress={() => Purchases.restorePurchases()} />
      <Button title="Privacy policy" onPress={() => Linking.openURL('https://tidepool.app/privacy')} />
      <Button title="Terms of use" onPress={() => Linking.openURL('https://tidepool.app/terms')} />
      <Button title="Accessibility" onPress={() => Linking.openURL('https://tidepool.app/accessibility')} />
      <Button
        title="Delete account"
        color="#b91c1c"
        onPress={() => Alert.alert('Delete account?', 'This removes your notes for good.', [
          { text: 'Cancel', style: 'cancel' },
          { text: 'Delete', style: 'destructive', onPress: deleteAccount },
        ])}
      />
    </View>
  )
}
""",
    "app/paywall.tsx": """import { Button, Text, View } from 'react-native'
import Purchases from 'react-native-purchases'

export default function Paywall() {
  async function subscribe() {
    const offerings = await Purchases.getOfferings()
    const monthly = offerings.current?.monthly
    if (monthly) await Purchases.purchasePackage(monthly)
  }

  return (
    <View>
      <Text>Tidepool Plus</Text>
      <Text>$4.99 per month. Renews automatically until you cancel in your App Store or Google Play settings.</Text>
      <Button title="Subscribe" onPress={subscribe} />
    </View>
  )
}
""",
    "supabase/migrations/20260101000000_init.sql": """create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  display_name text
);
alter table public.profiles enable row level security;
create policy "Owners read their profile" on public.profiles
  for select to authenticated using ((select auth.uid()) = id);
""",
}

# A minimal signup so signup-gated rules run.
SIGNUP = {
    "app/signup/page.tsx": """'use client'
import { createClient } from '@/lib/supabase/client'

export default function SignUp() {
  async function go(email: string, password: string) {
    await createClient().auth.signUp({ email, password })
  }
  return <button onClick={() => go('a', 'b')}>Sign up</button>
}
""",
}

EXPO_MIN = {
    "package.json": json.dumps({"dependencies": {"expo": "~54.0.0", "react-native": "0.81.0"}}),
    "app.json": json.dumps({"expo": {"name": "x", "ios": {"privacyManifests": {}}}}),
}
CAPACITOR_MIN = {
    "package.json": json.dumps({"dependencies": {"@capacitor/core": "^7.0.0", "@capacitor/ios": "^7.0.0",
                                                 "@capacitor/push-notifications": "^7.0.0",
                                                 "@capacitor/camera": "^7.0.0"}}),
    "capacitor.config.json": json.dumps({"appId": "app.x", "appName": "X", "webDir": "dist"}),
}


class CleanFixtureTests(ScanTestCase):
    """The false-positive guard: apps that do everything right produce zero findings."""

    def test_clean_nextjs_supabase_app_has_zero_findings(self):
        findings, notes = scan_tree(CLEAN_APP)
        self.assertEqual([], describe(findings))
        self.assertTrue(any("S03, S04 skipped" in n for n in notes))

    @unittest.skipUnless(HAS_GIT, "git not installed")
    def test_clean_app_as_git_repo_has_zero_findings(self):
        findings, _ = scan_tree(CLEAN_APP, git_repo=True)
        self.assertEqual([], describe(findings))

    def test_clean_capacitor_variant_has_zero_findings(self):
        findings, notes = scan_tree(merged(CLEAN_APP, CAPACITOR_EXTRA))
        self.assertEqual([], describe(findings))
        self.assertFalse(any("M01" in n for n in notes), "store rules must run for a Capacitor app")

    def test_clean_expo_variant_has_zero_findings(self):
        findings, notes = scan_tree(EXPO_APP)
        self.assertEqual([], describe(findings))
        self.assertFalse(any("M01" in n for n in notes), "store rules must run for an Expo app")


class SecretsTests(ScanTestCase):
    def test_S01_public_prefix_on_secret_name(self):
        files = {
            ".env.local": f"NEXT_PUBLIC_OPENAI_API_KEY={OPENAI_KEY}\nNEXT_PUBLIC_DB_PASSWORD=hunter22\n",
            "lib/ai.ts": "export const key = process.env.NEXT_PUBLIC_OPENAI_API_KEY\n",
            "src/db.ts": "const pw = import.meta.env.VITE_DB_PASSWORD\n",
        }
        hits = self.fires("S01", files)
        self.assertEqual(3, len(hits), describe(hits))  # one per distinct variable name
        self.assertTrue(all(OPENAI_KEY not in h.evidence and "hunter22" not in h.evidence for h in hits))

    def test_S01_publishable_names_do_not_fire(self):
        self.quiet("S01", {
            ".env": "NEXT_PUBLIC_SUPABASE_ANON_KEY=x\nNEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_x\nVITE_SUPABASE_URL=x\n",
            "lib/x.ts": "process.env.NEXT_PUBLIC_POSTHOG_KEY; process.env.SUPABASE_SERVICE_ROLE_KEY\n",
        })

    def test_S02_hardcoded_stripe_key(self):
        hits = self.fires("S02", {"lib/stripe.ts": f"export const stripe = new Stripe('{STRIPE_LIVE}')\n"})
        self.assertNotIn(STRIPE_LIVE, hits[0].evidence)
        self.assertIn("rotate", hits[0].fix)
        self.assertEqual("lib/stripe.ts:1", hits[0].where)

    def test_S02_service_role_jwt_fires_and_anon_jwt_does_not(self):
        self.fires("S02", {"lib/admin.js": f"const key = '{SERVICE_JWT}'\n"})
        self.quiet("S02", {"lib/client.js": f"const key = '{ANON_JWT}'\n"})

    def test_S02_env_file_outside_git_is_skipped_but_example_is_scanned(self):
        self.quiet("S02", {".env.local": f"STRIPE_SECRET_KEY={STRIPE_LIVE}\n"})
        self.fires("S02", {".env.example": f"STRIPE_SECRET_KEY={STRIPE_LIVE}\n"})

    def test_S02_placeholder_values_do_not_fire(self):
        self.quiet("S02", {".env.example": "STRIPE_SECRET_KEY=sk_live_your_key_here_xxxxxxxxxxxx\n"})

    @unittest.skipUnless(HAS_GIT, "git not installed")
    def test_S03_tracked_env_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_tree(root, {".env": "API_URL=x\n", ".env.example": "API_URL=\n", ".gitignore": ".env\n"})
            git(root, "init", "-q")
            git_commit_all(root, force=(".env",))
            findings, _ = scan.run(root, ".", scan.select_rules("S03"))
        self.assertEqual([".env:1"], [f.where for f in findings])

    def test_S03_skipped_with_note_outside_git(self):
        findings, notes = scan_tree({".env": "A=1\n"}, "S03")
        self.assertEqual([], findings)
        self.assertTrue(any("not a git repo" in n and "S03" in n for n in notes))

    @unittest.skipUnless(HAS_GIT, "git not installed")
    def test_S04_secret_only_in_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git(root, "init", "-q")
            write_tree(root, {"lib/pay.ts": f"const k = '{STRIPE_LIVE}'\n"})
            git_commit_all(root, "add key")
            write_tree(root, {"lib/pay.ts": "const k = process.env.STRIPE_SECRET_KEY\n"})
            git_commit_all(root, "move key to env")
            findings, notes = scan.run(root, ".", scan.select_rules("S04"))
            md = scan.render("scan.py", ".", findings, "md", notes)
        self.assertEqual(1, len(findings), describe(findings))
        self.assertIn("lib/pay.ts", findings[0].evidence)
        self.assertRegex(findings[0].evidence, r"commit [0-9a-f]{7,}")
        self.assertNotIn(STRIPE_LIVE, md)
        self.assertTrue(any("gitleaks" in n for n in notes))

    @unittest.skipUnless(HAS_GIT, "git not installed")
    def test_S04_secret_still_in_tree_is_left_to_S02(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git(root, "init", "-q")
            write_tree(root, {"lib/pay.ts": f"const k = '{STRIPE_LIVE}'\n"})
            git_commit_all(root)
            findings, _ = scan.run(root, ".", scan.select_rules("S02,S04"))
        self.assertEqual(["S02"], [f.id for f in findings])

    def test_S05_gitignore_without_env_rule(self):
        hits = self.fires("S05", {".env.local": "A=1\n", ".gitignore": "node_modules\n.env.local\n"})
        self.assertIn(".env", hits[0].evidence)
        missing = self.fires("S05", {"src/x.ts": "process.env.API_URL\n"})
        self.assertEqual(".gitignore (missing)", missing[0].where)

    def test_S05_env_star_and_star_env_cover_it(self):
        self.quiet("S05", {".env.local": "A=1\n", ".gitignore": ".env*\n"})
        self.quiet("S05", {"app.py": "import os\nos.environ['X']\n", ".gitignore": "*.env\n"})
        self.quiet("S05", {"README.md": "no env here\n"})

    def test_S06_service_role_in_use_client_file(self):
        hits = self.fires("S06", {"app/admin/page.tsx": "'use client'\nconst k = process.env.SUPABASE_SERVICE_ROLE_KEY\n"})
        self.assertEqual("P0", hits[0].severity)
        likely = self.fires("S06", {"components/Admin.tsx": "const k = process.env.SUPABASE_SERVICE_ROLE_KEY\n"})
        self.assertEqual("P1", likely[0].severity)

    def test_S06_server_files_do_not_fire(self):
        self.quiet("S06", {
            "lib/supabase/admin.ts": "createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!)\n",
            "app/api/admin/route.ts": "createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!)\n",
            "supabase/functions/cleanup/index.ts": "Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')\n",
            "app/actions.tsx": "'use server'\nprocess.env.SUPABASE_SERVICE_ROLE_KEY\n",
            "components/Note.tsx": "// never import the service_role client here\nexport default function Note() { return null }\n",
        })

    def test_S06_error_message_naming_the_variable_does_not_fire(self):
        # Seen in a real repo: a 'use client' component whose error text names the env var.
        self.quiet("S06", {"components/Admins.tsx": "'use client'\nconst MESSAGES = {\n"
                           "  unavailable: \"Account management needs UCG_SUPABASE_SECRET_KEY on the server.\",\n}\n"})
        self.fires("S06", {"components/Admins.tsx": "'use client'\nconst key = process.env.UCG_SUPABASE_SECRET_KEY\n"})

    def test_S07_dangerously_allow_browser(self):
        self.fires("S07", {"lib/ai.ts": "new OpenAI({ apiKey, dangerouslyAllowBrowser: true })\n"})
        self.quiet("S07", {"lib/ai.ts": "new OpenAI({ apiKey: process.env.OPENAI_API_KEY })\n"})


class DatabaseTests(ScanTestCase):
    def test_S08_table_without_rls(self):
        hits = self.fires("S08", {"supabase/migrations/1.sql": "create table public.notes (id int);\ncreate table todos (id int);\n"})
        self.assertEqual(["supabase/migrations/1.sql:1", "supabase/migrations/1.sql:2"], [h.where for h in hits])

    def test_S08_quoted_mixed_case_and_rls_in_other_file(self):
        self.quiet("S08", {
            "supabase/migrations/1.sql": 'CREATE TABLE IF NOT EXISTS "public"."Todos" (id int);\n',
            "supabase/migrations/2.sql": "ALTER TABLE public.todos ENABLE ROW LEVEL SECURITY;\n",
        })

    def test_S08_other_schemas_temp_tables_and_comments_do_not_fire(self):
        self.quiet("S08", {"db/schema.sql": (
            "create table auth.x (id int);\ncreate table storage.y (id int);\ncreate table private.z (id int);\n"
            "create temp table scratch (id int);\n-- create table public.commented_out (id int);\n"
            "create function f() returns void as $$ begin create table public.inside_body (id int); end $$ language plpgsql;\n"
        )})

    def test_S09_policy_with_true(self):
        hits = self.fires("S09", {"db/p.sql": (
            "create policy \"anyone writes\" on public.notes for insert with check (true);\n"
            "create policy \"public read\" on public.posts for select using (true);\n"
            "create policy \"all\" on notes using (true);\n"
        )})
        self.assertEqual(["P1", "P2", "P1"], [h.severity for h in hits])

    def test_S09_auth_uid_and_service_role_policies_do_not_fire(self):
        self.quiet("S09", {"db/p.sql": (
            "create policy \"own rows\" on public.notes for all to authenticated\n"
            "  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);\n"
            "create policy \"Service role to everything\" on public.notes for all to service_role using (true);\n"
        )})

    def test_S10_security_definer_without_revoke(self):
        hits = self.fires("S10", {"db/f.sql": (
            "create or replace function public.add_credits(n int) returns void\n"
            "language plpgsql security definer as $$ begin update profiles set credits = credits + n; end $$;\n"
        )})
        self.assertEqual(["P1", "P2"], sorted(h.severity for h in hits))

    def test_S10_revoked_trigger_and_invoker_functions_do_not_fire(self):
        self.quiet("S10", {"db/f.sql": (
            "create function public.add_credits(n int) returns void language sql security definer\n"
            "  set search_path = '' as $$ select 1 $$;\n"
            "revoke execute on function public.add_credits(int) from public, anon;\n"
            "create function public.handle_new_user() returns trigger language plpgsql security definer\n"
            "  set search_path = '' as $$ begin return new; end $$;\n"
            "create function public.plain() returns int language sql as $$ select 1 $$;\n"
            "create function private.helper() returns int language sql security definer as $$ select 1 $$;\n"
        )})

    def test_S11_view_without_security_invoker(self):
        self.fires("S11", {"db/v.sql": "create or replace view public.leaderboard as select * from profiles;\n"})
        self.fires("S11", {"db/v.sql": "create view v with (security_invoker = false) as select 1;\n"})

    def test_S11_invoker_in_statement_or_later_alter(self):
        self.quiet("S11", {"db/v.sql": (
            "create view public.a with (security_invoker = on) as select 1;\n"
            "create view b as select 1;\nalter view b set (security_invoker = true);\n"
            "create view private.c as select 1;\n"
        )})

    def test_S12_public_bucket(self):
        hits = self.fires("S12", {
            "db/s.sql": "insert into storage.buckets (id, name, public) values ('ids', 'ids', true);\n",
            "scripts/setup.ts": "await supabase.storage.createBucket('uploads', {\n  public: true,\n})\n",
            "supabase/config.toml": "[storage.buckets.avatars]\npublic = true\n",
        })
        self.assertEqual(3, len(hits), describe(hits))
        self.assertIn("ids", hits[0].evidence + hits[1].evidence + hits[2].evidence)
        self.fires("S12", {"db/s.sql": "update storage.buckets set public = true where id = 'x';\n"})

    def test_S12_private_bucket_does_not_fire(self):
        self.quiet("S12", {
            "db/s.sql": "insert into storage.buckets (id, name, public, allowed_mime_types)\n"
                        "values ('docs', 'docs', false, array['image/png', 'application/pdf']);\n",
            "scripts/setup.ts": "await supabase.storage.createBucket('docs', { public: false })\n",
        })

    def test_S13_open_firebase_rules(self):
        self.fires("S13", {"firestore.rules": "service cloud.firestore {\n  match /{doc=**} {\n    allow read, write: if true;\n  }\n}\n"})
        self.fires("S13", {"storage.rules": "allow read, write: if request.time < timestamp.date(2026, 10, 1);\n"})
        self.fires("S13", {"database.rules.json": '{"rules": {".read": true, ".write": false}}\n'})

    def test_S13_owner_rules_do_not_fire(self):
        self.quiet("S13", {
            "firestore.rules": "match /users/{uid} {\n  allow read, write: if request.auth != null && request.auth.uid == uid;\n}\n",
            "database.rules.json": '{"rules": {".read": false, "users": {"$uid": {".read": "auth.uid === $uid"}}}}\n',
        })

    def test_S14_client_writes_credits(self):
        hits = self.fires("S14", {"components/Usage.tsx": (
            "'use client'\nexport async function reset(supabase, id) {\n"
            "  await supabase.from('profiles').update({ credits: 999, is_admin: true }).eq('id', id)\n}\n"
        )})
        self.assertIn("credits", hits[0].evidence)
        self.fires("S14", {"src/Upgrade.jsx": "await setDoc(doc(db, 'users', uid), { plan: 'pro' })\n"})

    def test_S14_chat_role_and_server_writes_do_not_fire(self):
        self.quiet("S14", {
            "components/Chat.tsx": "'use client'\nawait supabase.from('messages').insert({ role: 'user', content: text })\n",
            "app/api/stripe/route.ts": "await admin.from('profiles').update({ plan: 'plus' })\n",
            "components/Profile.tsx": "'use client'\nawait supabase.from('profiles').update({ display_name: name })\n",
        })


class AppCodeTests(ScanTestCase):
    def test_S15_token_in_local_storage(self):
        self.fires("S15", {"src/auth.ts": "localStorage.setItem('access_token', data.session.access_token)\n"})
        self.fires("S15", {"src/auth.ts": "sessionStorage.setItem(KEY, jwt)\n"})

    def test_S15_theme_cart_and_author_do_not_fire(self):
        self.quiet("S15", {"src/prefs.ts": (
            "localStorage.setItem('theme', 'dark')\nsessionStorage.setItem('cart', JSON.stringify(cart))\n"
            "localStorage.setItem('authorFilter', name)\n"
        )})

    def test_S16_raw_html_sinks(self):
        hits = self.fires("S16", {"components/Post.tsx": (
            "export const Post = ({ html }) => <div dangerouslySetInnerHTML={{ __html: html }} />\n"
            "export const B = ({ html }) => <div dangerouslySetInnerHTML={{ __html: html }} />\n"
        )})
        self.assertEqual("P1", hits[0].severity)
        self.assertIn("2 in this file", hits[0].evidence)
        sanitized = self.fires("S16", {"src/render.js": "import DOMPurify from 'dompurify'\nel.innerHTML = DOMPurify.sanitize(html)\n"})
        self.assertEqual("P2", sanitized[0].severity)
        self.fires("S16", {"src/App.vue": "<template><div v-html=\"body\"></div></template>\n"})

    def test_S16_json_ld_and_clearing_do_not_fire(self):
        self.quiet("S16", {
            "app/page.tsx": "<script\n  type=\"application/ld+json\"\n  dangerouslySetInnerHTML={{ __html: JSON.stringify(ld) }}\n/>\n",
            "src/list.js": "list.innerHTML = ''\n",
            "src/list.test.js": "document.body.innerHTML = '<div></div>'\n",
        })

    def test_S17_unverified_stripe_webhook(self):
        self.fires("S17", {"app/api/webhooks/stripe/route.ts": (
            "export async function POST(req: Request) {\n  const event = await req.json()\n"
            "  if (event.type === 'checkout.session.completed') { await grantAccess(event) }\n}\n"
        )})

    def test_S17_verified_webhook_and_handler_module_do_not_fire(self):
        self.quiet("S17", {
            "app/api/webhooks/stripe/route.ts": (
                "export async function POST(req: Request) {\n"
                "  const event = stripe.webhooks.constructEvent(await req.text(), req.headers.get('stripe-signature')!, secret)\n"
                "  if (event.type === 'checkout.session.completed') {}\n}\n"),
            "lib/webhook-handlers.ts": "export function handle(event: Stripe.Event) {\n  switch (event.type) { case 'invoice.paid': return }\n}\n",
            "app/webhook.py": "event = stripe.Webhook.construct_event(payload, sig, secret)\nif event['type'] == 'invoice.paid': pass\n",
        })

    def test_S18_interpolated_sql(self):
        self.fires("S18", {"src/db.ts": "const rows = await db.query(`SELECT * FROM users WHERE id = ${id}`)\n"})
        self.fires("S18", {"src/db.js": "pool.query(\"select * from users where email = '\" + email + \"'\")\n"})
        self.fires("S18", {"app/db.py": "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n"})
        self.fires("S18", {"src/p.ts": "await prisma.$queryRawUnsafe(`DELETE FROM posts WHERE id = ${id}`)\n"})

    def test_S18_tagged_templates_and_params_do_not_fire(self):
        self.quiet("S18", {
            "src/db.ts": ("await sql`select * from users where id = ${id}`\n"
                          "await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`\n"
                          "await db.execute(sql`delete from posts where id = ${id}`)\n"
                          "await db.query('select * from users where id = $1', [id])\n"
                          "const q = useQuery(`posts-${id}`)\n"),
            "app/db.py": "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))\n",
        })

    def test_S19_open_cors(self):
        hits = self.fires("S19", {"server/index.js": "app.use(cors())\n"})
        self.assertEqual("P1", hits[0].severity)
        creds = self.fires("S19", {"server/index.js": "app.use(cors({ origin: true, credentials: true }))\n"})
        self.assertEqual("P0", creds[0].severity)
        self.fires("S19", {"vercel.json": '{"headers": [{"source": "/api/(.*)", "headers": [{"key": "Access-Control-Allow-Origin", "value": "*"}]}]}\n'})
        self.fires("S19", {"supabase/functions/_shared/cors.ts": "export const corsHeaders = { 'Access-Control-Allow-Origin': '*' }\n"})

    def test_S19_explicit_origins_and_vite_dev_server_do_not_fire(self):
        self.quiet("S19", {
            "server/index.js": "app.use(cors({ origin: ['https://tidepool.app'], credentials: true }))\n",
            "vite.config.ts": "export default { server: { cors: { origin: true } } }\n",
        })

    def test_S20_source_maps_and_debug(self):
        self.fires("S20", {"next.config.js": "module.exports = { productionBrowserSourceMaps: true }\n"})
        self.fires("S20", {"vite.config.ts": "export default defineConfig({\n  build: {\n    sourcemap: true,\n  },\n})\n"})
        self.fires("S20", {"mysite/settings.py": "DEBUG = True\n"})
        self.fires("S20", {"app.py": "if __name__ == '__main__':\n    app.run(host='0.0.0.0', debug=True)\n"})
        self.fires("S20", {"webpack.prod.js": "module.exports = { mode: 'production', devtool: 'source-map' }\n"})

    def test_S20_hidden_maps_and_dev_settings_do_not_fire(self):
        self.quiet("S20", {
            "vite.config.ts": "export default defineConfig({ build: { sourcemap: 'hidden' }, css: { devSourcemap: true } })\n",
            "mysite/settings_dev.py": "DEBUG = True\n",
            "mysite/settings.py": "DEBUG = os.environ.get('DEBUG') == '1'\n",
        })

    def test_S21_fast_hash_for_passwords(self):
        self.fires("S21", {"lib/auth.ts": "const hash = crypto.createHash('sha256').update(password).digest('hex')\n"})
        self.fires("S21", {"auth.py": "digest = hashlib.md5(\n    pwd.encode()\n).hexdigest()\n"})

    def test_S21_reset_token_and_file_hash_do_not_fire(self):
        self.quiet("S21", {
            "lib/reset.ts": "user.resetPasswordToken = crypto.createHash('sha256').update(token).digest('hex')\n",
            "lib/etag.ts": "const etag = createHash('sha1').update(body).digest('hex')\n",
        })

    def test_S22_routes_without_rate_limit(self):
        hits = self.fires("S22", {"app/api/chat/route.ts": "export async function POST() {}\n",
                                  "package.json": json.dumps({"dependencies": {"next": "15"}})})
        self.assertIn("Supabase Auth", hits[0].why)
        self.fires("S22", {"requirements.txt": "flask==3.0\n", "app.py": "app = Flask(__name__)\n"})

    def test_S22_limiter_dependency_or_code_does_not_fire(self):
        self.quiet("S22", {"app/api/chat/route.ts": "export async function POST() {}\n",
                           "package.json": json.dumps({"dependencies": {"@upstash/ratelimit": "2"}})})
        self.quiet("S22", {"supabase/functions/chat/index.ts": "import { Ratelimit } from 'npm:@upstash/ratelimit'\n"})
        self.quiet("S22", {"app/api/chat/route.ts": "if (!(await checkRateLimit(user.id))) return tooMany()\n"})

    def test_S23_signup_without_captcha(self):
        self.fires("S23", SIGNUP)
        self.quiet("S23", merged(SIGNUP, {"components/Captcha.tsx": "import { Turnstile } from '@marsidev/react-turnstile'\n"}))

    def test_S24_open_redirect(self):
        self.fires("S24", {"app/login/page.tsx": "'use client'\nconst params = useSearchParams()\nrouter.push(params.get('next'))\n"})
        self.fires("S24", {"app/auth/callback/route.ts": (
            "const next = searchParams.get('next') ?? '/'\nif (code) {\n  await exchange(code)\n  if (ok) {\n"
            "    return NextResponse.redirect(`${origin}${next}`)\n  }\n}\n")})
        self.fires("S24", {"server.js": "app.get('/go', (req, res) => {\n  res.redirect(req.query.returnTo)\n})\n"})

    def test_S24_guarded_redirect_does_not_fire(self):
        self.quiet("S24", {"app/auth/callback/route.ts": (
            "let next = searchParams.get('next') ?? '/'\nif (!next.startsWith('/')) next = '/'\n"
            "return NextResponse.redirect(`${origin}${next}`)\n")})
        self.quiet("S24", {"app/page.tsx": "const tab = searchParams.get('tab')\nrouter.push('/settings')\n"})


WEB = {"app/page.tsx": "export default function Home() { return <main><h1>Hi</h1></main> }\n"}


class LegalTests(ScanTestCase):
    def test_L01_google_fonts_link(self):
        hits = self.fires("L01", {"index.html": (
            '<link rel="preconnect" href="https://fonts.gstatic.com">\n'
            '<link href="https://fonts.googleapis.com/css2?family=Roboto" rel="stylesheet">\n')})
        self.assertEqual(1, len(hits))  # one per file
        self.fires("L01", {"src/app.css": "@import url('https://fonts.googleapis.com/css2?family=Lora');\n"})

    def test_L01_next_font_csp_and_docs_do_not_fire(self):
        self.quiet("L01", {
            "app/layout.tsx": "import { Lora } from 'next/font/google'\n",
            "next.config.js": "const csp = \"font-src 'self' https://fonts.gstatic.com\"\n",
            "docs/fonts.md": "We used to load fonts.googleapis.com.\n",
        })

    def test_L02_tracker_without_consent(self):
        hits = self.fires("L02", {
            "app/layout.tsx": "<Script src=\"https://www.googletagmanager.com/gtag/js?id=G-1\" />\n",
            "lib/analytics.ts": "import posthog from 'posthog-js'\nposthog.init(key)\n",
        })
        self.assertEqual(2, len(hits))  # one per tracker

    def test_L02_consent_tool_or_cookieless_analytics_do_not_fire(self):
        self.quiet("L02", {"app/layout.tsx": "import 'vanilla-cookieconsent/dist/cookieconsent.css'\ngtag('config', 'G-1')\n"})
        self.quiet("L02", {"app/layout.tsx": (
            "import { Analytics } from '@vercel/analytics/react'\n<Script data-domain=\"x\" src=\"https://plausible.io/js/script.js\" />\n"
            "const peak = Math.max(...waveform.amplitude)\nconst heap = new MinHeap()\n")})

    def test_L03_session_replay(self):
        hits = self.fires("L03", {"sentry.client.config.ts": "Sentry.init({ integrations: [Sentry.replayIntegration()] })\n"})
        self.assertIn("no input-masking", hits[0].evidence)
        masked = self.fires("L03", {"app/layout.tsx": "<Script src=\"https://static.hotjar.com/c/hotjar-1.js\" />\n",
                                    "components/Form.tsx": "<input data-hj-suppress name=\"card\" />\n"})
        self.assertIn("input masking found", masked[0].evidence)

    def test_L04_missing_legal_pages(self):
        hits = self.fires("L04", merged(WEB, {"package.json": json.dumps({"dependencies": {"stripe": "18"}})}))
        by_page = {h.evidence.split("'")[1]: h.severity for h in hits}
        self.assertEqual({"privacy": "P1", "terms": "P1", "accessibility": "P2", "refunds": "P2"}, by_page)
        self.assertEqual("HUMAN", hits[0].owner)
        self.assertTrue(hits[0].where.startswith("app/privacy/page.tsx"))
        tracked = self.fires("L04", merged(WEB, {"app/layout.tsx": "gtag('config', 'G-1')\n"}))
        self.assertIn("cookies", " ".join(h.evidence for h in tracked))

    def test_L04_pages_links_and_external_policies_count(self):
        self.quiet("L04", merged(WEB, {
            "app/(legal)/privacy-policy/page.tsx": "export default function P() { return <p>Privacy</p> }\n",
            "components/Footer.tsx": "<a href=\"https://legal.tidepool.app/tos\">Terms</a>\n<Link href=\"/accessibility\">A11y</Link>\n",
        }))

    def test_L04_photos_route_is_not_terms(self):
        hits = self.fires("L04", merged(WEB, {"app/photos/page.tsx": "<p>Photos</p>\n", "app/privacy/page.tsx": "<p/>\n",
                                              "app/accessibility/page.tsx": "<p/>\n"}))
        self.assertEqual(["terms"], [h.evidence.split("'")[1] for h in hits])

    def test_L05_prechecked_marketing_box(self):
        self.fires("L05", {"components/Signup.tsx": (
            "<label>\n  <input type=\"checkbox\" name=\"newsletter\" defaultChecked />\n  Send me product updates\n</label>\n")})
        self.fires("L05", {"components/Signup.tsx": "const [marketingOptIn, setMarketingOptIn] = useState(true)\n"})
        self.fires("L05", {"src/Form.vue": "<input type=\"checkbox\" checked> I agree to receive offers\n"})

    def test_L05_unchecked_bound_and_remember_me_do_not_fire(self):
        self.quiet("L05", {"components/Login.tsx": (
            "<label><input type=\"checkbox\" defaultChecked /> Remember me</label>\n"
            "<p>By signing in you agree to our <a href=\"/terms\">Terms</a>.</p>\n"
            "<label><input type=\"checkbox\" name=\"newsletter\" /> Newsletter</label>\n"
            "<input type=\"checkbox\" checked={subscribed} onChange={toggle} /> Subscribe\n"
            "const [agreed, setAgreed] = useState(false)\n")})

    def test_L06_signup_without_age_check(self):
        hits = self.fires("L06", SIGNUP)
        self.assertIn("COPPA", hits[0].why)
        self.quiet("L06", merged(SIGNUP, {"app/terms/page.tsx": "<p>You must be 16 or older to use this.</p>\n"}))

    def test_L06_not_run_without_signup(self):
        findings, notes = scan_tree(WEB, "L06")
        self.assertEqual([], findings)
        self.assertTrue(any("no signup flow" in n for n in notes))

    def test_L07_ai_sdk_dependency(self):
        hits = self.fires("L07", {"package.json": json.dumps({"dependencies": {"ai": "5", "@ai-sdk/openai": "2"}})})
        self.assertEqual(1, len(hits))
        self.assertIn("@ai-sdk/openai", hits[0].evidence)
        self.fires("L07", {"requirements.txt": "anthropic>=0.40\n"})

    def test_L08_signup_without_account_deletion(self):
        self.fires("L08", SIGNUP)
        self.quiet("L08", merged(SIGNUP, {"app/api/account/route.ts": "await admin.auth.admin.deleteUser(user.id)\n"}))

    def test_L09_image_without_alt(self):
        hits = self.fires("L09", {"components/Hero.tsx": (
            "<img src=\"/hero.png\" className=\"w-full\" />\n<Image\n  src={logo}\n  width={40}\n/>\n")})
        self.assertIn("2 images", hits[0].evidence)

    def test_L09_empty_alt_bound_alt_and_icons_do_not_fire(self):
        self.quiet("L09", {
            "components/Hero.tsx": "<img src=\"/line.svg\" alt=\"\" />\n<Image\n  src={p.src}\n  width={1}\n  alt={p.title}\n/>\n",
            "components/Gallery.tsx": "import { Image } from 'lucide-react'\n<Image className=\"h-4 w-4\" />\n",
            "src/Card.svelte": "<img {src} {alt} />\n",
            "components/Avatar.tsx": "<img src={url} {...props} />\n",
        })

    def test_L10_focus_outline_removed(self):
        self.fires("L10", {"components/Button.tsx": "<button className=\"px-4 outline-none\">Go</button>\n"})
        self.fires("L10", {"src/styles.css": "*:focus { outline: none; }\n"})

    def test_L10_focus_replacement_does_not_fire(self):
        self.quiet("L10", {
            "components/Input.tsx": "<input className=\"border focus:outline-none focus:ring-2 focus:ring-teal-600\" />\n",
            "components/ui/button.tsx": "const b = 'outline-none focus-visible:ring-[3px]'\n",
            "src/styles.css": "button:focus { outline: none; box-shadow: 0 0 0 3px #0f766e; }\n",
        })

    def test_L11_html_without_lang(self):
        self.fires("L11", {"index.html": "<!doctype html>\n<html>\n<head><title>Tidepool</title></head>\n</html>\n"})
        self.fires("L11", {"app/layout.tsx": "return (\n  <html>\n    <body>{children}</body>\n  </html>\n)\n"})

    def test_L11_lang_present_does_not_fire(self):
        self.quiet("L11", {"index.html": "<html lang=\"en\">\n</html>\n", "src/app.html": "<html lang=\"%lang%\">\n",
                           "pages/_document.tsx": "<Html lang=\"en\">\n"})

    def test_L12_email_without_unsubscribe(self):
        hits = self.fires("L12", {"package.json": json.dumps({"dependencies": {"resend": "6"}})})
        self.assertEqual("HUMAN", hits[0].owner)
        self.quiet("L12", {"package.json": json.dumps({"dependencies": {"resend": "6"}}),
                           "emails/news.tsx": "<a href={url}>Unsubscribe</a>\n"})

    def test_L13_subscription_without_renewal_terms(self):
        self.fires("L13", {"app/api/checkout/route.ts": "stripe.checkout.sessions.create({ mode: 'subscription' })\n",
                           "app/pricing/page.tsx": "<p>Plus: $9</p>\n"})
        self.fires("L13", {"package.json": json.dumps({"dependencies": {"react-native-purchases": "9"}})})

    def test_L13_renewal_text_present(self):
        self.quiet("L13", {"app/api/checkout/route.ts": "stripe.checkout.sessions.create({ mode: 'subscription' })\n",
                           "app/pricing/page.tsx": "<p>$9/month, cancel anytime</p>\n"})

    def test_L14_user_content_without_report(self):
        hits = self.fires("L14", {"supabase/migrations/1.sql": "create table public.comments (id int);\n"})
        self.assertIn("DSA", hits[0].why)
        self.fires("L14", {"lib/reviews.ts": "await supabase.from('reviews').insert(review)\n"})

    def test_L14_report_path_ai_chat_and_blog_posts_do_not_fire(self):
        self.quiet("L14", {"supabase/migrations/1.sql": "create table public.comments (id int);\ncreate table public.reports (id int);\n"})
        self.quiet("L14", {"package.json": json.dumps({"dependencies": {"openai": "5"}}),
                           "supabase/migrations/1.sql": "create table public.messages (id int, role text, content text);\n"})
        self.quiet("L14", {"content/posts/hello.md": "# Hello\n", "app/blog/[slug]/page.tsx": "getPost(slug)\n"})


class DesignCopyTests(ScanTestCase):
    def test_D01_purple_gradient(self):
        hits = self.fires("D01", {"components/Hero.tsx": (
            "<section className=\"bg-gradient-to-r from-purple-600 via-indigo-500 to-blue-500\">\n"
            "<div className=\"bg-linear-to-br from-violet-500 to-fuchsia-400\" />\n")})
        self.assertIn("2 in this file", hits[0].evidence)
        self.fires("D01", {"src/app.css": ".hero { background: linear-gradient(135deg, #7C3AED, #2563eb); }\n"})
        self.quiet("D01", {"components/Hero.tsx": "<div className=\"bg-gradient-to-r from-teal-600 to-emerald-500 text-purple-700\" />\n"})

    def test_D02_gradient_text(self):
        self.fires("D02", {"components/Title.tsx": "<h1 className=\"bg-gradient-to-r from-sky-500 to-teal-400 bg-clip-text text-transparent\">Hi</h1>\n"})
        self.fires("D02", {"src/app.css": "h1 { -webkit-background-clip: text; background-clip: text; }\n"})
        self.quiet("D02", {"components/Title.tsx": "<h1 className=\"text-slate-900\">Hi</h1>\n"})

    def test_D03_glassmorphism(self):
        three = "<nav className=\"backdrop-blur-md\" />\n<div className=\"backdrop-blur\" />\n<aside className=\"backdrop-blur-sm\" />\n"
        self.fires("D03", {"components/Shell.tsx": three})
        self.quiet("D03", {"components/Shell.tsx": "<nav className=\"backdrop-blur-md\" />\n<div className=\"backdrop-blur\" />\n"})

    def test_D04_colored_left_border_cards(self):
        self.fires("D04", {"components/Cards.tsx": (
            "<div className=\"border-l-4 border-blue-500 p-4\" />\n<div className=\"border-l-4 border-l-emerald-500 p-4\" />\n")})
        self.quiet("D04", {"components/Cards.tsx": "<div className=\"border-l-4 border-blue-500 p-4\" />\n"})

    def test_D05_many_lucide_icons(self):
        names = [f"Icon{i}" for i in range(20)]
        files = {"components/A.tsx": f"import {{ {', '.join(names[:10])} }} from 'lucide-react'\n",
                 "components/B.tsx": "import {\n  " + ",\n  ".join(names[10:]) + "\n} from 'lucide-react'\n"}
        hits = self.fires("D05", files)
        self.assertIn("20 distinct", hits[0].evidence)
        files["components/B.tsx"] = "import { " + ", ".join(names[10:19]) + ", Icon0 } from 'lucide-react'\n"
        self.quiet("D05", files)

    def test_D06_inter_typeface(self):
        self.fires("D06", {"app/layout.tsx": "import { Inter } from 'next/font/google'\nconst inter = Inter({ subsets: ['latin'] })\n"})
        self.fires("D06", {"tailwind.config.ts": "theme: { extend: { fontFamily: {\n  sans: ['Inter', 'sans-serif'],\n} } }\n"})
        self.fires("D06", {"src/app.css": "@theme { --font-sans: \"Inter\", system-ui; }\n"})

    def test_D06_other_fonts_do_not_fire(self):
        self.quiet("D06", {"app/layout.tsx": "import { Inter_Tight, Lora } from 'next/font/google'\n",
                           "src/app.css": "body { font-family: 'Source Serif 4', serif; }\n/* Interstitial styles */\n"})

    def test_D07_emoji_in_copy(self):
        hits = self.fires("D07", {"app/page.tsx": "<li>\U0001F680 Fast</li>\n<li>\u2728 Simple</li>\n",
                                  "app/about/page.tsx": "<p>Made with \u2764\ufe0f in Oregon</p>\n"})
        self.assertIn("3 emoji", hits[0].evidence)

    def test_D07_emoji_in_comments_or_under_three_do_not_fire(self):
        self.quiet("D07", {"app/page.tsx": "// \U0001F680 launch day\n{/* \u2728 sparkle */}\n<p>\U0001F30A Tide</p>\n<p>\u2600 Sun</p>\n"})

    def test_D08_scroll_reveal_everywhere(self):
        self.fires("D08", {"components/Sections.tsx": "<motion.div whileInView={{ opacity: 1 }} />\n" * 5})
        self.quiet("D08", {"components/Sections.tsx": "<motion.div whileInView={{ opacity: 1 }} />\n" * 4})

    def test_D09_filler_texture(self):
        self.fires("D09", {"app/page.tsx": "<div className=\"absolute inset-0 bg-grid-slate-100\" />\n"})
        self.fires("D09", {"public/noise.png": PNG})
        self.quiet("D09", {"app/page.tsx": "<p>Whole grain loaves every morning, and a grid of tide times.</p>\n"})

    def test_D10_cursor_effects(self):
        self.fires("D10", {"components/Cursor.tsx": "<div className=\"cursor-none\"><CustomCursor /></div>\n"})
        self.fires("D10", {"src/app.css": "body { cursor: none; }\n"})
        self.quiet("D10", {"app/page.tsx": "<h2>Customer spotlight</h2>\n<p>In the spotlight this month</p>\n"})

    def test_D11_em_dashes(self):
        hits = self.fires("D11", {"app/page.tsx": "<p>Fast \u2014 simple \u2014 yours</p>\n<p>One \u2014 two \u2014 three &mdash; go</p>\n"})
        self.assertIn("5 em dashes", hits[0].evidence)
        self.quiet("D11", {"app/page.tsx": "// a \u2014 b \u2014 c \u2014 d \u2014 e \u2014 f\n<p>One \u2014 two</p>\n"})

    def test_D12_buzzwords(self):
        hits = self.fires("D12", {"app/page.tsx": (
            "<h1>Elevate your workflow</h1>\n<p>A seamless, robust platform. Seamless sync.</p>\n")})
        self.assertIn("seamless \u00d72", hits[0].evidence)
        self.fires("D12", {"app/page.tsx": "<p>Whether you're a surfer or a biologist, look no further. Take it to the next level.</p>\n"})

    def test_D12_words_inside_html_script_blocks_are_not_copy(self):
        self.quiet("D12", {"index.html": "<html lang=en><p>Plain words.</p>\n<script>\n"
                                         "var demo = 'seamless robust innovative leverage';\n</script></html>\n"})
        self.fires("D12", {"index.html": "<html lang=en><p>A seamless, robust, innovative tool.</p><script>x()</script></html>\n"})

    def test_D12_under_three_or_in_comments_do_not_fire(self):
        self.quiet("D12", {"app/page.tsx": "// seamless robust innovative leverage\n<p>A seamless sync and a robust log.</p>\n"})

    def test_D13_capitalized_lorem_ipsum_alone(self):
        self.fires("D13", {"components/About.tsx": "<p>Lorem ipsum dolor sit amet, consectetur.</p>\n"})

    def test_D13_placeholder_content(self):
        hits = self.fires("D13", {"components/Team.tsx": "<p>Lorem ipsum dolor sit amet</p>\n<p>John Doe, CEO of Acme</p>\n",
                                  "components/Soon.tsx": "<span>Dark mode coming soon</span>\n"})
        self.assertEqual(2, len(hits))  # one per file
        self.assertIn("Never invent", hits[0].fix)
        self.fires("D13", {"components/Avatar.tsx": "<img src=\"https://i.pravatar.cc/100\" alt=\"\" />\n"})

    def test_D13_form_placeholders_and_labels_do_not_fire(self):
        self.quiet("D13", {"components/Form.tsx": (
            "<input placeholder=\"Jane Doe\" />\n<input placeholder=\"you@example.com\" type=\"email\" />\n"
            "<label htmlFor=\"company\">Company Name</label>\n<input id=\"company\" />\n"
            "<Field label=\"Your Name\" />\n")})

    def test_D14_unverifiable_social_proof(self):
        self.fires("D14", {"app/page.tsx": "<p>Trusted by 10,000+ teams</p>\n"})
        self.fires("D14", {"app/page.tsx": "<p>Rated 4.9/5 stars by 2k+ users</p>\n"})
        self.fires("D14", {"app/page.tsx": "<h2>The #1 tide app</h2>\n"})
        self.quiet("D14", {"app/page.tsx": "<p>Issue&#1; tide tables for 12 beaches</p>\n<p className=\"text-[#1a1a1a]\">x</p>\n"})

    def test_D15_scaffold_title_and_assets(self):
        hits = self.fires("D15", {
            "index.html": "<title>Vite + React + TS</title>\n<link rel=\"icon\" type=\"image/svg+xml\" href=\"/vite.svg\" />\n",
            "public/vite.svg": "<svg/>",
            "public/next.svg": "<svg/>",
        })
        self.assertEqual(["index.html:1", "index.html:2", "public/next.svg"], sorted(h.where for h in hits))
        self.fires("D15", {"app/layout.tsx": "export const metadata = { title: 'Create Next App', description: 'Generated by create next app' }\n"})

    def test_D16_missing_seo_basics(self):
        hits = self.fires("D16", WEB)
        self.assertEqual(5, len(hits), describe(hits))
        self.assertIn("public/robots.txt (missing)", [h.where for h in hits])
        next_app = self.fires("D16", merged(WEB, {"package.json": json.dumps({"dependencies": {"next": "15"}})}))
        self.assertIn("app/robots.ts (missing)", [h.where for h in next_app])

    def test_D16_static_site_basics_present(self):
        self.quiet("D16", {"index.html": ("<html lang=\"en\"><head><link rel=\"icon\" href=\"/favicon.ico\">"
                                          "<meta property=\"og:image\" content=\"/og.png\"></head></html>\n"),
                           "public/robots.txt": "User-agent: *\nAllow: /\n", "public/sitemap.xml": "<urlset/>\n",
                           "public/404.html": "<h1>Not found</h1>\n"})

    def test_D16_skipped_for_store_only_expo_app(self):
        self.quiet("D16", merged(EXPO_MIN, {"app/index.tsx": "export default () => <Text>Hi</Text>\n"}))

    def test_D17_multiple_h1(self):
        self.fires("D17", {"app/page.tsx": "<h1>One</h1>\n<section><h1 className=\"x\">Two</h1></section>\n"})
        self.quiet("D17", {"app/page.tsx": "<h1>One</h1>\n{/* <h1>old</h1> */}\n<h2>Two</h2>\n"})
        self.fires("D17", {"app/page.tsx": (
            "export default function Page() {\n  return (\n    <main>\n      <h1>One</h1>\n"
            "      <button onClick={() => setOpen(true)}>Open</button>\n      <h1>Two</h1>\n    </main>\n  )\n}\n")})

    def test_D18_ai_crawlers_blocked(self):
        hits = self.fires("D18", {"public/robots.txt": "User-agent: GPTBot\nUser-agent: ClaudeBot\nDisallow: /\n\nUser-agent: *\nAllow: /\n"})
        self.assertIn("ClaudeBot", hits[0].evidence)
        self.assertEqual("HUMAN", hits[0].owner)
        self.fires("D18", {"app/robots.ts": "rules: [{ userAgent: 'GPTBot', disallow: '/' }]\n"})

    def test_D18_partial_or_general_rules_do_not_fire(self):
        self.quiet("D18", {"public/robots.txt": "User-agent: GPTBot\nDisallow: /private\n\nUser-agent: *\nDisallow: /\n"})

    def test_D19_stock_shadcn_theme(self):
        self.fires("D19", {"components.json": "{}", "app/globals.css": ":root {\n  --primary: oklch(0.205 0 0);\n}\n"})
        self.fires("D19", {"components.json": "{}", "src/index.css": ":root { --primary: 222.2 47.4% 11.2%; }\n"})

    def test_D19_custom_primary_or_no_shadcn_do_not_fire(self):
        self.quiet("D19", {"components.json": "{}", "app/globals.css": ":root { --primary: oklch(0.52 0.09 190); }\n"})
        self.quiet("D19", {"app/globals.css": ":root { --primary: oklch(0.205 0 0); }\n"})


class StoreTests(ScanTestCase):
    def test_M01_capacitor_remote_server_url(self):
        hits = self.fires("M01", merged(CAPACITOR_MIN, {"capacitor.config.json": json.dumps(
            {"appId": "app.x", "webDir": "dist", "server": {"url": "https://myapp.vercel.app"}})}))
        self.assertIn("4.2", hits[0].why)

    def test_M01_capacitor_live_reload_url(self):
        hits = self.fires("M01", merged(CAPACITOR_MIN, {"capacitor.config.ts": (
            "const config = {\n  appId: 'app.x',\n  server: {\n    url: 'http://192.168.1.20:5173',\n    cleartext: true,\n  },\n}\n")}))
        self.assertIn("Live-reload", hits[0].why)

    def test_M01_no_server_url_does_not_fire(self):
        self.quiet("M01", merged(CAPACITOR_MIN, {"capacitor.config.ts": "const config = { appId: 'x', server: { androidScheme: 'https' } }\n"}))

    def test_M02_thin_capacitor_wrapper(self):
        hits = self.fires("M02", {"package.json": json.dumps({"dependencies": {
            "@capacitor/core": "7", "@capacitor/ios": "7", "@capacitor/splash-screen": "7", "@capacitor/haptics": "7"}}),
            "capacitor.config.json": "{}"})
        self.assertIn("1 (@capacitor/haptics)", hits[0].evidence)
        self.quiet("M02", CAPACITOR_MIN)

    def test_M03_native_signup_without_deletion(self):
        hits = self.fires("M03", merged(EXPO_MIN, {"app/sign-up.tsx": "await supabase.auth.signUp({ email, password })\n"}))
        self.assertIn("5.1.1", hits[0].why)

    def test_M03_needs_native_and_signup(self):
        findings, notes = scan_tree(SIGNUP, "M03")
        self.assertEqual([], findings)
        self.assertTrue(any("no native app" in n for n in notes))

    def test_M04_google_login_without_apple(self):
        self.fires("M04", merged(EXPO_MIN, {"app/login.tsx": "supabase.auth.signInWithOAuth({ provider: 'google' })\n"}))
        self.quiet("M04", merged(EXPO_MIN, {"app/login.tsx": (
            "supabase.auth.signInWithOAuth({ provider: 'google' })\nsupabase.auth.signInWithIdToken({ provider: 'apple', token })\n")}))

    def test_M05_web_checkout_without_iap(self):
        hits = self.fires("M05", merged(EXPO_MIN, {"app/upgrade.tsx": "Linking.openURL('https://buy.stripe.com/test_123')\n"}))
        self.assertEqual("HUMAN", hits[0].owner)
        self.quiet("M05", merged(EXPO_MIN, {
            "app/upgrade.tsx": "Linking.openURL('https://buy.stripe.com/test_123')\n",
            "package.json": json.dumps({"dependencies": {"expo": "54", "react-native-purchases": "9"}})}))

    def test_M06_iap_without_restore(self):
        iap = {"package.json": json.dumps({"dependencies": {"expo": "54", "react-native-purchases": "9"}}), "app.json": EXPO_MIN["app.json"]}
        self.fires("M06", iap)
        self.quiet("M06", merged(iap, {"app/settings.tsx": "<Button title=\"Restore Purchases\" onPress={restore} />\n"}))

    def test_M07_target_sdk_below_floor(self):
        android = {"android/app/build.gradle": "android {\n  defaultConfig {\n    targetSdkVersion 34\n  }\n}\n"}
        hits = self.fires("M07", android)
        self.assertEqual("P0", hits[0].severity)
        self.assertIn(str(scan.PLAY_TARGET_SDK_FLOOR), hits[0].evidence)
        variables = self.fires("M07", {"android/app/build.gradle": "targetSdkVersion rootProject.ext.targetSdkVersion\n",
                                       "android/variables.gradle": "ext {\n  targetSdkVersion = 35\n}\n"})
        self.assertEqual("android/variables.gradle:2", variables[0].where)

    def test_M07_target_sdk_at_floor_is_P2(self):
        floor = scan.PLAY_TARGET_SDK_FLOOR
        hits = self.fires("M07", {"android/app/build.gradle.kts": f"android {{\n  defaultConfig {{\n    targetSdk = {floor}\n  }}\n}}\n"})
        self.assertEqual("P2", hits[0].severity)
        expo = self.fires("M07", {"package.json": EXPO_MIN["package.json"], "app.json": json.dumps({"expo": {"plugins": [
            ["expo-build-properties", {"android": {"targetSdkVersion": floor}}]]}})})
        self.assertEqual("P2", expo[0].severity)

    def test_M07_above_floor_or_no_literal_does_not_fire(self):
        self.quiet("M07", {"android/app/build.gradle": f"targetSdkVersion {scan.PLAY_TARGET_SDK_FLOOR + 1}\n"})
        self.quiet("M07", {"android/app/build.gradle": "targetSdk = flutter.targetSdkVersion\n", "pubspec.yaml": "name: x\n"})

    def test_M08_sensitive_android_permission(self):
        hits = self.fires("M08", {"android/app/build.gradle": "", "android/app/src/main/AndroidManifest.xml": (
            "<manifest>\n  <uses-permission android:name=\"android.permission.READ_CONTACTS\" />\n"
            "  <uses-permission android:name=\"android.permission.QUERY_ALL_PACKAGES\"/>\n</manifest>\n")})
        self.assertEqual(2, len(hits))
        self.fires("M08", {"package.json": EXPO_MIN["package.json"], "app.json": json.dumps(
            {"expo": {"android": {"permissions": ["ACCESS_BACKGROUND_LOCATION"]}}})})

    def test_M08_removed_blocked_and_commented_permissions_do_not_fire(self):
        self.quiet("M08", {"android/app/build.gradle": "", "android/app/src/main/AndroidManifest.xml": (
            "<manifest>\n  <uses-permission android:name=\"android.permission.READ_MEDIA_IMAGES\" tools:node=\"remove\" />\n"
            "  <!-- <uses-permission android:name=\"android.permission.READ_SMS\" /> -->\n</manifest>\n")})
        self.quiet("M08", {"package.json": EXPO_MIN["package.json"], "app.json": json.dumps(
            {"expo": {"android": {"permissions": ["CAMERA"], "blockedPermissions": ["android.permission.READ_CONTACTS"]}}})})

    def test_M09_missing_privacy_manifest(self):
        hits = self.fires("M09", {"ios/App/App.xcodeproj/project.pbxproj": "{}\n"})
        self.assertEqual("P1", hits[0].severity)
        expo = self.fires("M09", {"package.json": EXPO_MIN["package.json"], "app.json": json.dumps({"expo": {"name": "x"}})})
        self.assertEqual("P2", expo[0].severity)
        self.quiet("M09", {"ios/App/App.xcodeproj/project.pbxproj": "{}\n", "ios/App/App/PrivacyInfo.xcprivacy": "<plist/>\n"})

    def test_M10_vague_usage_descriptions(self):
        hits = self.fires("M10", {"ios/App/App.xcodeproj/project.pbxproj": "{}", "ios/App/PrivacyInfo.xcprivacy": "",
                                  "ios/App/App/Info.plist": (
            "<key>NSCameraUsageDescription</key>\n<string>Camera access</string>\n"
            "<key>NSMicrophoneUsageDescription</key>\n<string>This app needs access to your microphone.</string>\n"
            "<key>NSLocationWhenInUseUsageDescription</key>\n<string></string>\n")})
        self.assertEqual(3, len(hits))
        self.fires("M10", {"package.json": EXPO_MIN["package.json"], "app.json": json.dumps({"expo": {"ios": {"infoPlist": {
            "NSCameraUsageDescription": "Allow $(PRODUCT_NAME) to access your camera"}}}})})

    def test_M10_specific_description_does_not_fire(self):
        self.quiet("M10", {"package.json": EXPO_MIN["package.json"], "app.json": json.dumps({"expo": {"ios": {"infoPlist": {
            "NSCameraUsageDescription": "Scan a receipt so the amount fills in automatically."}}}})})

    def test_M11_ipad_supported(self):
        hits = self.fires("M11", {"package.json": EXPO_MIN["package.json"], "app.json": json.dumps({"expo": {"ios": {"supportsTablet": True}}})})
        self.assertEqual("HUMAN", hits[0].owner)
        self.fires("M11", {"ios/App/App.xcodeproj/project.pbxproj": "TARGETED_DEVICE_FAMILY = \"1,2\";\n"})
        self.quiet("M11", {"ios/App/App.xcodeproj/project.pbxproj": "TARGETED_DEVICE_FAMILY = 1;\n"})

    def test_store_rules_skipped_for_web_only_app(self):
        findings, notes = scan_tree(WEB, "store")
        self.assertEqual([], findings)
        self.assertTrue(any("no native app found" in n for n in notes))



class RealRepoRegressionTests(ScanTestCase):
    """False positives seen when scanning real repos, each pinned by a negative case."""

    def test_S02_synthetic_test_fixtures_do_not_fire(self):
        pem_header = "-----BEGIN " + "RSA PRIVATE KEY-----"
        self.quiet("S02", {
            "tests/test_redact.py": (
                'FAKE_SECRET = "ghp_' + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8" + '"\n'
                f'PEM = ("{pem_header}\\n" "MIIBBBBBBBBBBAAAAAAAAAA+/abc" "-----END RSA PRIVATE KEY-----")\n'),
            "test/api/env.test.ts": 'const env = { SUPABASE_SECRET_KEY: "sb_secret_' + "0123456789abcdefghijklmnopqrstuv" + '" }\n',
            "lib/keys.ts": f'if (pem.startsWith("{pem_header}")) return "pkcs1"\n',
            "supabase/seed.ts": "const key = '" + ".".join((_b64({"alg": "HS256"}), _b64({"iss": "supabase-demo", "role": "service_role"}),
                                                           "EGIM96RAZx35lJzdJsyH")) + "'\n",
            "src/diag.test.ts": 'new Error("ECONNREFUSED mongodb://' + 'u:p@host")\n',
            "docker-compose.yml": "DATABASE_URL: postgres://" + "app:app@db:5432/app\n",
            "lib/notes.py": '"""Docker-style URLs (postgres://' + 'app:app@db). are skipped."""\n',
            "tests/secret-tool.bats": "check_db_url 'postgresql://postgres.TEST_KEY_ref:" + "asT7MBnQdXEtg7iX@x.pooler.supabase.com:5432/postgres'\n",
            "keepalive.env": f"SUPABASE_SECRET_KEY={STRIPE_LIVE}\n",  # a *.env file outside git: where secrets belong
        })
        # A long password on an internal hostname is a real credential.
        self.fires("S02", {".env.example": "MONGO_URL=mongodb://" + "svc:sNrSL90d4ZMK7GuwAAmhPTvN@mongoprod01:27017/app\n"})

    def test_S02_real_looking_pem_still_fires(self):
        body = base64.b64encode(bytes((i * 73 + 41) % 256 for i in range(120))).decode()
        self.fires("S02", {"deploy/key.pem": "-----BEGIN " + f"PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"})

    def test_S18_identifier_and_constant_interpolation_do_not_fire(self):
        self.quiet("S18", {
            "store/sqlite.py": ('conn.execute(f"PRAGMA user_version={LAYOUT_VERSION}")\n'
                                'conn.execute(f"INSERT INTO {temp} ({cols}) SELECT {cols} FROM {table}")\n'
                                'conn.execute(f"SELECT * FROM {table} WHERE id = ?", (row_id,))\n'),
            "src/db/seed.ts": ('await client.query(\n  "update public.profiles set status = \'active\' " +\n'
                               '    "where id = $1 and status <> \'active\'",\n  [id],\n)\n'
                               'await db.query(`SELECT * FROM ${TABLE} WHERE id = $1`, [id])\n'),
        })

    def test_L02_tracker_hosts_in_a_crawler_script_do_not_fire(self):
        self.quiet("L02", {"scripts/check_sites.py": 'IGNORED = ("google-analytics.com", "googletagmanager.com", "connect.facebook.net")\n'})
        self.quiet("L01", {"scripts/audit.py": 'FONT_HOSTS = ["fonts.googleapis.com", "fonts.gstatic.com"]\n'})

    def test_D17_h1_in_separate_return_branches_does_not_fire(self):
        self.quiet("D17", {"src/routes/practice.tsx": (
            "export function Practice({ state }) {\n  if (state.phase === 'failed') {\n    return (\n"
            "      <main><h1>The practice game stopped</h1></main>\n    )\n  }\n"
            "  return (\n    <main><h1>Practice</h1></main>\n  )\n}\n"
            "const components = { h1: (p) => <h1 className=\"x\" {...p} />, h2: (p) => <h2 {...p} /> }\n")})

    def test_D07_text_symbols_are_not_emoji(self):
        self.quiet("D07", {"src/List.tsx": "<span aria-hidden=\"true\">\\u2726</span>\n",
                           "src/Play.tsx": "<p>\\u2713 saved</p>\n<button>\\u2715</button>\n<p>\\u2605 \\u2660 \\u2630</p>\n"})

    def test_D13_labels_and_field_maps_do_not_fire(self):
        self.quiet("D13", {"app/admin/new-client/page.tsx": (
            "<label htmlFor=\"companyName\" className=\"block text-sm font-medium text-gray-700 mb-2\">\n"
            "  Company Name *\n</label>\n<th>Your Name</th>\n"
            "const defaults = { aioCompanyName: \"Company Name\" }\n")})
        self.fires("D13", {"app/page.tsx": "<footer><p>\\u00a9 2026 Company Name. All rights reserved.</p></footer>\n"})

    def test_L10_menu_item_focus_background_and_chart_internals_do_not_fire(self):
        self.quiet("L10", {
            "components/ui/select.tsx": "\"relative flex w-full select-none items-center outline-none focus:bg-accent focus:text-accent-foreground\"\n",
            "components/ui/chart.tsx": "\"[&_.recharts-sector]:outline-none [&_.recharts-surface]:outline-none\"\n",
        })

    def test_S16_constant_theme_script_does_not_fire_but_injected_data_does(self):
        self.quiet("S16", {"components/theme-script.tsx": (
            "const themeScript = `(function(){ document.documentElement.dataset.theme = localStorage.theme })()`\n"
            "export const ThemeScript = () => <script dangerouslySetInnerHTML={{ __html: themeScript }} />\n")})
        self.fires("S16", {"app/layout.tsx": "<script dangerouslySetInnerHTML={{ __html: `window.__DATA__ = ${JSON.stringify(data)}` }} />\n"})

    @unittest.skipUnless(HAS_GIT, "git not installed")
    def test_S05_tracked_env_with_ignore_rule_is_left_to_S03(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_tree(root, {".env": "A=1\n", "src/x.ts": "process.env.A\n"})
            git(root, "init", "-q")
            git_commit_all(root)
            write_tree(root, {".gitignore": ".env*\n"})
            findings, _ = scan.run(root, ".", scan.select_rules("S03,S05"))
        self.assertEqual(["S03"], [f.id for f in findings])

    def test_S02_pem_header_in_an_assertion_does_not_fire(self):
        header = "-----BEGIN " + "PRIVATE KEY-----"
        self.quiet("S02", {"tests/core/test_signing.py": (
            "def test_private_pem_is_pkcs8_pem() -> None:\n    pem = Signer.generate('k').private_pem()\n"
            f"    assert pem.startswith(b\"{header}\")\n\n\ndef test_from_pem_rejects_rsa() -> None:\n"
            "    rsa_pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(\n"
            "        encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8)\n"
            "    with pytest.raises(ValueError):\n        Signer.from_pem(rsa_pem)\n" * 3)})

    def test_S05_builtin_and_ci_env_reads_do_not_count(self):
        self.quiet("S05", {"web/vite.config.ts": "export default { base: import.meta.env.BASE_URL, define: { sha: process.env.GITHUB_SHA } }\n",
                           "cypress.config.js": "const cache = process.env.CYPRESS_CACHE_FOLDER\nif (process.env.NODE_ENV === 'production') {}\n",
                           "web/scripts/e2e.mjs": "spawn('npx', ['vite'], { stdio: 'inherit', env: process.env })\n"})
        self.fires("S05", {"src/config.ts": "const { STRIPE_SECRET_KEY } = process.env\n"})

    def test_L02_saved_framework_page_is_not_the_site(self):
        saved = ('<!DOCTYPE html><html lang="en-us"><head><meta charSet="utf-8" data-next-head=""/>'
                 '<script src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>'
                 '<script src="/_next/static/chunks/main.js"></script></head><body><h1>A</h1><h1>B</h1></body></html>\n')
        findings, _ = scan_tree({"eb.html": saved, "scrape.py": "print('hi')\n"})
        self.assertEqual([], describe(findings))

    def test_S16_static_markup_and_escaped_templates(self):
        self.quiet("S16", {"web/src/pages/home.ts": "root.innerHTML = `\n  <h1>Turing Machine OS</h1>\n  <p>Pick a demo.</p>\n`;\n"})
        escaped = self.fires("S16", {"web/src/panels/cpu.ts": (
            "import { escapeHtml } from '../util'\nnode.innerHTML = `<span>${escapeHtml(cpu.name)}</span>`\n")})
        self.assertEqual("P2", escaped[0].severity)

    def test_S23_points_at_the_signup_route_not_a_link_list(self):
        hits = self.fires("S23", {"app/(auth)/signin/page.tsx": "const authPages = ['/signin', '/signup']\n",
                                  "app/(auth)/signup/page.tsx": "export default function SignUp() { return <form /> }\n"})
        self.assertEqual("app/(auth)/signup/page.tsx:1", hits[0].where)

# The rules table from the spec: id -> (default severity, area, owner).
SPEC_TABLE = {
    "S01": ("P0", "secrets", "AGENT"), "S02": ("P0", "secrets", "HUMAN"), "S03": ("P0", "secrets", "HUMAN"),
    "S04": ("P0", "secrets", "HUMAN"), "S05": ("P1", "secrets", "AGENT"), "S06": ("P0", "secrets", "AGENT"),
    "S07": ("P0", "secrets", "AGENT"), "S08": ("P0", "data", "AGENT"), "S09": ("P1", "data", "AGENT"),
    "S10": ("P1", "data", "AGENT"), "S11": ("P1", "data", "AGENT"), "S12": ("P1", "data", "AGENT"),
    "S13": ("P0", "data", "AGENT"), "S14": ("P1", "data", "AGENT"), "S15": ("P1", "auth", "AGENT"),
    "S16": ("P1", "abuse", "AGENT"), "S17": ("P0", "abuse", "AGENT"), "S18": ("P1", "abuse", "AGENT"),
    "S19": ("P1", "ops", "AGENT"), "S20": ("P1", "ops", "AGENT"), "S21": ("P1", "auth", "AGENT"),
    "S22": ("P2", "abuse", "AGENT"), "S23": ("P2", "abuse", "AGENT"), "S24": ("P2", "auth", "AGENT"),
    "L01": ("P1", "legal", "AGENT"), "L02": ("P1", "legal", "AGENT"), "L03": ("P1", "legal", "AGENT"),
    "L04": ("P1", "legal", "HUMAN"), "L05": ("P1", "legal", "AGENT"), "L06": ("P2", "legal", "HUMAN"),
    "L07": ("P2", "legal", "AGENT"), "L08": ("P1", "legal", "AGENT"), "L09": ("P1", "legal", "AGENT"),
    "L10": ("P2", "legal", "AGENT"), "L11": ("P2", "legal", "AGENT"), "L12": ("P1", "legal", "HUMAN"),
    "L13": ("P1", "legal", "AGENT"), "L14": ("P1", "legal", "AGENT"),
    "D01": ("P3", "design", "AGENT"), "D02": ("P3", "design", "AGENT"), "D03": ("P3", "design", "AGENT"),
    "D04": ("P3", "design", "AGENT"), "D05": ("P3", "design", "AGENT"), "D06": ("P3", "design", "AGENT"),
    "D07": ("P3", "copy", "AGENT"), "D08": ("P3", "design", "AGENT"), "D09": ("P3", "design", "AGENT"),
    "D10": ("P3", "design", "AGENT"), "D11": ("P3", "copy", "AGENT"), "D12": ("P3", "copy", "AGENT"),
    "D13": ("P1", "copy", "HUMAN"), "D14": ("P1", "legal", "HUMAN"), "D15": ("P2", "seo", "AGENT"),
    "D16": ("P2", "seo", "AGENT"), "D17": ("P2", "seo", "AGENT"), "D18": ("P3", "seo", "HUMAN"),
    "D19": ("P3", "design", "AGENT"),
    "M01": ("P0", "store", "AGENT"), "M02": ("P1", "store", "HUMAN"), "M03": ("P0", "store", "AGENT"),
    "M04": ("P1", "store", "AGENT"), "M05": ("P1", "store", "HUMAN"), "M06": ("P1", "store", "AGENT"),
    "M07": ("P0", "store", "AGENT"), "M08": ("P1", "store", "AGENT"), "M09": ("P1", "store", "AGENT"),
    "M10": ("P2", "store", "AGENT"), "M11": ("P3", "store", "HUMAN"),
}


class SuppressionTests(ScanTestCase):
    """The owner can accept a finding with a reason; every suppression shows up in the notes."""

    BUZZ = "<p>A seamless, robust, innovative platform.</p>\n"

    def test_inline_comment_on_the_line_above_suppresses(self):
        files = {"app/page.tsx": "{/* polish-website-ignore D12 demo copy for the rule bench */}\n" + self.BUZZ}
        findings, notes = scan_tree(files, "D12")
        self.assertEqual([], describe(findings))
        self.assertTrue(any("suppressed by the owner" in n and "demo copy for the rule bench" in n for n in notes), notes)

    def test_file_comment_suppresses_only_the_named_rule(self):
        files = {"app/page.tsx": "// polish-website-ignore-file D12 marketing copy approved by the owner\n"
                                 "<p>Lorem ipsum dolor sit amet</p>\n" + self.BUZZ}
        findings, _ = scan_tree(files, "D12,D13")
        self.assertEqual(["D13"], [f.id for f in findings])

    def test_comment_without_a_reason_is_not_applied(self):
        files = {"app/page.tsx": "{/* polish-website-ignore D12 */}\n" + self.BUZZ}
        findings, notes = scan_tree(files, "D12")
        self.assertEqual(["D12"], [f.id for f in findings])
        self.assertTrue(any("has no reason" in n for n in notes), notes)

    def test_root_ignore_file_with_glob(self):
        files = {"app/page.tsx": self.BUZZ,
                 ".polish-website-ignore": "# owner-accepted findings\nD12 app/* tone chosen by the brand team\nD06\n"}
        findings, notes = scan_tree(files, "D12")
        self.assertEqual([], describe(findings))
        self.assertTrue(any(".polish-website-ignore line 3" in n for n in notes), notes)

    def test_suppression_elsewhere_does_not_leak(self):
        files = {"app/page.tsx": self.BUZZ,
                 "app/other.tsx": "// polish-website-ignore-file D12 only this file is accepted\n<p>ok</p>\n"}
        findings, _ = scan_tree(files, "D12")
        self.assertEqual(["D12"], [f.id for f in findings])


class RegistryAndCliTests(unittest.TestCase):
    def test_rules_match_spec_table(self):
        actual = {r.id: (r.severity, r.area, r.owner) for r in scan.RULES}
        self.assertEqual(SPEC_TABLE, actual)
        self.assertEqual(list(SPEC_TABLE), [r.id for r in scan.RULES])
        for r in scan.RULES:
            self.assertLess(len(r.title), 60, r.id)
            self.assertTrue(callable(r.check), r.id)

    def test_every_rule_id_has_a_named_test(self):
        names = " ".join(n for cls in (SecretsTests, DatabaseTests, AppCodeTests, LegalTests, DesignCopyTests, StoreTests,
                                       RealRepoRegressionTests)
                         for n in dir(cls) if n.startswith("test_"))
        missing = [r.id for r in scan.RULES if f"test_{r.id}_" not in names]
        self.assertEqual([], missing)

    def run_cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, SCAN, *args], capture_output=True, text=True, timeout=60)

    def test_list_rules_md_and_json(self):
        md = self.run_cli("--list-rules")
        self.assertEqual(0, md.returncode, md.stderr)
        for rule_id in SPEC_TABLE:
            self.assertIn(f"| {rule_id} |", md.stdout)
        js = self.run_cli("--list-rules", "--format", "json")
        self.assertEqual(len(SPEC_TABLE), len(json.loads(js.stdout)))

    def test_json_output_is_valid_and_exit_code_follows_fail_on(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(Path(tmp), {"lib/stripe.ts": f"new Stripe('{STRIPE_LIVE}')\n", "app/page.tsx": "<img src='/a.png'>\n"})
            result = self.run_cli(tmp, "--format", "json")
            self.assertEqual(1, result.returncode, result.stderr)  # P0 present, default --fail-on P0
            data = json.loads(result.stdout)
            self.assertEqual("scan.py", data["tool"])
            self.assertIn("S02", [f["id"] for f in data["findings"]])
            self.assertEqual(0, self.run_cli(tmp, "--fail-on", "none").returncode)
            self.assertEqual(0, self.run_cli(tmp, "--only", "L09", "--fail-on", "P0").returncode)
            self.assertEqual(1, self.run_cli(tmp, "--only", "L09", "--fail-on", "P1").returncode)

    def test_only_accepts_ids_and_areas(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(Path(tmp), merged(WEB, {"lib/stripe.ts": f"new Stripe('{STRIPE_LIVE}')\n"}))
            data = json.loads(self.run_cli(tmp, "--only", "secrets,D16", "--format", "json").stdout)
        self.assertEqual({"S02", "D16"}, {f["id"] for f in data["findings"]})

    def test_usage_errors_exit_2(self):
        self.assertEqual(2, self.run_cli(".", "--only", "Z99").returncode)
        self.assertEqual(2, self.run_cli("/nonexistent/polish-website-path").returncode)

    def test_planted_secrets_never_appear_in_md_or_json(self):
        files = {
            "lib/stripe.ts": f"export const stripe = new Stripe('{STRIPE_LIVE}')\n",
            "lib/admin.ts": f"const serviceKey = '{SERVICE_JWT}'\n",
            ".env.example": f"NEXT_PUBLIC_OPENAI_KEY={OPENAI_KEY}\n",
            "components/Chat.tsx": f"'use client'\nconst ai = new OpenAI({{ apiKey: '{OPENAI_KEY}', dangerouslyAllowBrowser: true }})\n",
        }
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(Path(tmp), files)
            out_file = Path(tmp) / "report.md"
            outputs = [self.run_cli(tmp, "--format", fmt).stdout for fmt in ("md", "json")]
            self.run_cli(tmp, "--out", str(out_file))
            outputs.append(out_file.read_text(encoding="utf-8"))
        for text in outputs:
            self.assertIn("S02", text)
            for secret in (STRIPE_LIVE, SERVICE_JWT, OPENAI_KEY):
                self.assertNotIn(secret, text)
                self.assertNotIn(secret[8:-4], text)

    def test_walk_skips_dependencies_build_output_large_and_binary_files(self):
        files = {
            "node_modules/pkg/index.js": f"const k = '{STRIPE_LIVE}'\n",
            ".next/server/app.js": f"const k = '{STRIPE_LIVE}'\n",
            "android/app/build/intermediates/x.js": f"const k = '{STRIPE_LIVE}'\n",
            "big.js": "// padding\n" * 100_000 + f"const k = '{STRIPE_LIVE}'\n",
            "blob.bin": b"\x00\x01" + STRIPE_LIVE.encode(),
            "package-lock.json": f'{{"x": "{STRIPE_LIVE}"}}\n',
        }
        findings, _ = scan_tree(files, "S02")
        self.assertEqual([], describe(findings))

    def test_findings_have_all_fields_and_relative_where(self):
        findings, _ = scan_tree(merged(WEB, SIGNUP, {"lib/stripe.ts": f"new Stripe('{STRIPE_LIVE}')\n"}))
        self.assertTrue(findings)
        for f in findings:
            for field in ("where", "evidence", "why", "fix", "verify"):
                self.assertTrue(getattr(f, field).strip(), f"{f.id} {field}")
            self.assertLessEqual(len(f.evidence), 160, f.id)
            self.assertFalse(f.where.startswith("/"), f.where)


if __name__ == "__main__":
    unittest.main()
