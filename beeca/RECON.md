# BeeCA — recon (coordinator, initial pass)

**Goal:** steal the "Первопромпт" (First Prompt) from `admin-bv5kavo6.beeca.avitoctf.ru/`,
which requires an **mTLS client certificate with `CN=admin`** (only the IT-lead has one).
Portal that issues named client certs: `portal-bv5kavo6.beeca.avitoctf.ru/`.
Author @v1ru55 (SPbCTF). Hard, Crypto+Web+Logic, **0 solves**, 1000 pts.

## Hosts
- `portal-bv5kavo6.beeca.avitoctf.ru` — React SPA (Vite). nginx/1.27.5.
- `admin-bv5kavo6.beeca.avitoctf.ru` — **403 "Для доступа требуется клиентский сертификат BeeCA"** (mTLS wall; `Connection: close` on fail).
- Internal (server-side only, name derived in JS): `certissue-bv5kavo6.internal` — where the **operator/approval** endpoint lives.

## Portal API (from bundle `/static/assets/index-CispjmHt.js`)
- `GET  /api/me` — session: `{authenticated, email, enrollment:{uuid, cn, status, serial}}`.
- `POST /api/enroll` (credentials same-origin) — creates enrollment → `{serial, cn, status}`; status `pending` needs **manual approval**, else `issued`.
- `GET  /api/cert` — downloads issued **`beeca-client.p12`** (password: `beeca`).
- `POST /api/feedback` `{request_id, message}` — "ускорить рассмотрение заявки"; a **moderator reviews manually**. ⚠️ The returned `message` is rendered with **`dangerouslySetInnerHTML`** (`feedback-echo`) → **stored/reflected XSS into whoever views it**.
- `GET/POST /login` (Google SSO), `POST /logout`.
- `POST /internal/cert?uuid=<id>&action=approve|decline` — the **operator** action (approve/decline enrollments). Operator console (`#/operator` route, or when on an `*.internal` host) shows: `action endpoint: https://certissue-<token>.internal/internal/cert?uuid=<id>&action=approve|decline`.
- Host logic: `lc={external:{prefix:"portal-",base:".beeca.avitoctf.ru"}, internal:{prefix:"certissue-",base:".internal"}}`; `Li()`=on internal host?; `Hd()` maps external token→`certissue-<token>.internal`.

## Policy strings in bundle
- `[policy] CN is derived from verified SSO identity`
- `[policy] manual approval` / "модератор посмотрит вручную"
- queen-seal renders `CN=<cn>`; operator seal renders `approver`.

## Working attack hypotheses (for agents)
1. **XSS/inject the moderator (operator).** Feedback `message` is `dangerouslySetInnerHTML`-rendered to the manual moderator. If the moderator views it in the **operator console** (which can call `/internal/cert` on the internal host / has an admin session), an injected script can approve our enrollment and/or drive the internal cert-issuance to mint a **CN=admin** cert. The "vibecoder bees" + "Первопромпт" flavor hints the moderator may be an **LLM/agent** → **prompt injection** in the feedback text to issue an admin cert. THIS IS THE LEADING LOGIC+WEB VECTOR.
2. **CN control at enroll.** CN is "SSO-derived" — probe whether the CSR/enroll lets us influence CN (display-name/email injection, extra RDNs, `admin\x00.me` null-byte, unicode-normalization) so the issued cert matches `CN=admin` at the admin's mTLS check (**parsing differential** between issuance and nginx `$ssl_client_s_dn_cn`).
3. **Crypto / CA.** Pull the `beeca-client.p12` (pw `beeca`), inspect the **CA cert + chain + sig alg + serial policy**. Look for: recoverable/weak CA key, predictable serials, an issuance oracle, or a cert-template flaw letting us self-request `CN=admin`. mTLS CN-matching differentials (RDN order, PrintableString vs UTF8String, trailing bytes).
4. **SSRF to `/internal/cert`.** If any portal endpoint proxies to the internal host, reach `certissue-bv5kavo6.internal/internal/cert?action=approve` directly.

## Blockers / unknowns to resolve first
- Does the portal require **Google SSO** to enroll/feedback, or do these work anonymously? (`/api/me` unauth first.)
- What does `POST /api/enroll` actually return anonymously vs authed? Is there a CSR upload or is the keypair server-side (p12 implies server-side keygen)?
- Exact mTLS check on admin host: nginx `ssl_verify_client` + CN match, or app-level `$ssl_client_s_dn`?

## Local artifacts
- `portal.js` — full portal bundle (grep it, it's minified but readable).
