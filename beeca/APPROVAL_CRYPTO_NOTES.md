# BeeCA — internal-issuer reach + crypto verdict (this pass)

Scope: the two live frontiers handed off — (1) can the internal issuer
(`certissue-bv5kavo6.internal`) be reached and made to approve/act, and (2) full crypto verdict on
the CA trust once a real leaf exists. Both resolved this pass with a live, working repro. **No flag
yet** — the remaining blocker is explained at the end.

## FRONTIER 1 — YES, the internal issuer IS reachable. Full repro.

**The bug:** nginx routes HTTPS virtual hosts by **SNI**, and `certissue-bv5kavo6.internal` is a
real, distinct `server{}` block on the same shared edge IP (`93.77.163.176`) as the portal/admin
vhosts — it is *not* protected by network segmentation, only by the fact that the name doesn't
publicly resolve. Prior passes (`WEBLOGIC_NOTES.md` §6, `CRYPTO_NOTES.md` §4) tested Host-header
spoofing *while connecting with a different SNI* (`curl -H "Host: certissue-....internal" https://
admin-bv5kavo6.../`) — that only reaches nginx's `default_server` fallback (still the portal app,
no `/internal/cert` route) because **SNI selection happens before Host-header routing** and an
unmatched SNI never reaches the real internal `server{}` block. The fix is to make **both** SNI and
Host equal the internal name, via curl's `--resolve` (which sets SNI from the request URL, not a
separate `-H` override):

```bash
curl -sk -X POST --resolve certissue-bv5kavo6.internal:443:93.77.163.176 \
  "https://certissue-bv5kavo6.internal/internal/cert?uuid=<UUID>&action=approve"
# -> {"ok":true,"status":"issued","uuid":"<UUID>"}
```

This is a genuine, real internal `server{}` block — `GET /` on it serves the same SPA shell,
`GET /api/me` is live (same backend), and **`/internal/cert` actually works** (200, real JSON),
unlike the `default_server` fallback which 404s on that route.

### What `/internal/cert` actually does (fully characterized)

- **Zero authentication required.** Tested with no cookie at all — `approve`/`decline` work
  identically with or without a session cookie. Trust here is **purely network-position-based**
  (only reachable if you know/forge the internal hostname), not app-level. A forged/tampered
  session JWT (`alg:none`, bad HMAC signature, claiming `email:"admin"`) is rejected identically on
  this host as on the portal (`{"authenticated":false}`) — **session validation itself is not
  weaker internally**, only `/internal/cert` skips auth entirely by design (it's meant to be called
  by a human/tool already inside the network).
- **Real DB lookup, no injection.** `uuid` must exactly match an existing enrollment record —
  garbage/random-v4/all-zero uuids all return `{"error":"not found"}`(effectively; body is bare
  `"not found"`). Tried SQL-injection-flavored payloads (`' OR '1'='1`, `%`, `*`), alternate
  identifier params (`id=`, `serial=` instead of `uuid=`) — all `"uuid required"`/`"not found"`, no
  injection, no alternate lookup key.
- **`action` is a strict enum**: only `approve`/`decline` accepted; `issue`, `reissue`, `admin`,
  `grant`, `elevate`, `promote`, `update`, `list` all rejected with `"action must be approve or
  decline"`.
- **Extra params are silently ignored, including `cn=`.** Tested `&cn=admin` both as (a) a no-op
  re-approval of an already-`issued` record, and (b) a **fresh** `decline` → `approve` state
  transition (to rule out "only applies on first issuance") — in both cases the resulting `cn`
  stayed exactly `shadowklesh@gmail.com`. **CN cannot be influenced through this endpoint under any
  parameter name tried** (`cn`, `email`, `subject`, `identity`, `user`, `name` — as query params,
  JSON body, and headers on `/api/enroll` reached via this same internal host too).
- **No other internal routes exist.** Fuzzed ~30 plausible paths on this vhost (`/internal/users`,
  `/internal/list`, `/internal/pending`, `/internal/approvals`, `/internal/queue`,
  `/internal/dashboard`, `/internal/review`, `/internal/moderate`, `/internal/export`,
  `/internal/db`, `/internal/sign`, `/internal/ca`, `/internal/ca.crt`, `/internal/ca-key`,
  `/internal/keys`, `/internal/root`, `/ca.crt`, `/ca.pem`, `/api/ca`, `/beeca.crt`, etc.) — every
  one is a plain Werkzeug 404 (genuinely unrouted), only `/internal/cert` is real.
- **No admin-side counterpart.** Guessed 9 plausible internal hostnames mirroring the
  `certissue-<token>.internal` pattern for the admin app (`admin-bv5kavo6.internal`,
  `hive-bv5kavo6.internal`, `queen-bv5kavo6.internal`, `moderator-/operator-bv5kavo6.internal`,
  etc.) — none of them hit a real vhost; all either TLS-handshake-then-empty-reply (no matching
  `server{}` block for that SNI at all) unlike the real `certissue-...` name which serves proper
  content. **The admin app has no equivalent DNS-obscurity bypass** — its only gate is the mTLS
  wall itself (see Frontier 2).

### What we used it for (real, demonstrated impact)

Used this to instantly self-approve the participant's own real, Google-authenticated `pending`
enrollment (`uuid=05e4cb4f-c01f-41f5-ab31-35179065ef52`, `cn=shadowklesh@gmail.com`,
`serial=4096`) — skipping the "5 business days manual review" entirely — then pulled the genuine
CA-signed `beeca-client.p12` via `/api/cert`. This **is** a real, exploitable authorization bypass
(unauthenticated actor can instantly approve/decline *any known* enrollment uuid) — but its blast
radius is capped by the fact that `uuid` must already be known, is a genuine random UUIDv4 (122
bits entropy, unenumerable), and there is no listing/enumeration endpoint anywhere on this service.
So it lets us **fast-track our own** enrollment, but not discover or hijack anyone else's
(specifically: not the admin's, which per the challenge is already `issued`, not `pending`, so
there's nothing to "approve" there even if we had the uuid).

## FRONTIER 2 — crypto verdict: CA cert unobtainable, sub-CA path dead, CN check is exact + app-level

### 2.1 Sub-CA / self-signing hypothesis: **definitively dead**

Full x509 text dump of our real, CA-issued leaf (`cn=shadowklesh@gmail.com`, serial 4096):

```
X509v3 Basic Constraints: critical
    CA:FALSE
X509v3 Key Usage: critical
    Digital Signature
X509v3 Extended Key Usage:
    TLS Web Client Authentication
```

`CA:FALSE` (critical) + no `keyCertSign` + client-auth-only EKU. No `AIA`/`CRL` extensions either.
This kills the "issued leaf can act as an unrestricted intermediate" theory outright — both by
explicit `BasicConstraints` and by `KeyUsage`, and OpenSSL's chain builder (which nginx uses) does
enforce `CA:FALSE` on any would-be intermediate. Not pursuing further.

### 2.2 The CA certificate itself: **could not be obtained anywhere**, despite an exhaustive hunt

- The issued `.p12` contains **exactly one** cert bag (our leaf) and one key bag — no CA/chain
  cert bundled (`openssl pkcs12 -info` confirms: single `Certificate bag`, no second
  `-----BEGIN CERTIFICATE-----` block for an issuer).
- `/api/cert` doesn't vary output on `Accept:` header (`x-pem-file`, `pem-certificate-chain`,
  `text/plain`) or query params (`?format=pem`, `?include=chain`, `?full=1`, `?chain=1`, `?ca=1`) —
  always the identical 2440-byte p12.
- `/api/enroll`'s JSON has no extra fields beyond `cn, fingerprint, private_key_pem, serial,
  status, uuid` — no `ca_pem`/`chain_pem`.
- Swept `/ca.crt`, `/ca.pem`, `/beeca.crt`, `/beeca-ca.crt`, `/BeeCA.crt`, `/cacert.pem`,
  `/pki/ca.crt`, `/root-ca.pem`, `/roots.pem`, `/api/ca`, plus bee-themed guesses (`/hive.crt`,
  `/queen.crt`, `/matka.crt`, `/apiary.crt`, `/honeycomb.pem`, `/BeeCA_root.pem`, etc.) on **all
  three** reachable vhosts (portal, admin — 403'd due to no-cert gate, and the internal issuer via
  the Frontier-1 bypass) — 404 everywhere real routing was reachable.
- Subdomain enumeration (`ca.`, `pki.`, `root.`, `crl.`, `trust.` × both bare and `-bv5kavo6`
  variants) all resolve to the same wildcard IP with no distinct vhost behavior.
- Re-tested the non-443 "open" ports (8080/8443/3000/5000/8000/9000) using the same
  SNI/Host-matching trick that worked for port 443 — all still give an instant empty reply
  regardless of hostname. Confirms prior notes: **genuine TCP tarpit, not a real service** on any
  of those ports, this SNI trick doesn't unlock them.
- TLS `CertificateRequest` (both TLS1.2/1.3) only leaks the CA's **subject DN**
  (`CN=BeeCA, O=BeeCA`), never key material — RFC 5246/8446 `certificate_authorities` is DN-only by
  spec, so this channel structurally cannot leak the modulus.

**Verdict: the CA certificate is not exposed anywhere on the public web surface.** The
weak-CA-key/factorization hypothesis (Fermat, ROCA, shared-prime GCD) is **untestable** without it
— you cannot factor or fingerprint a modulus you don't have, and RSA signatures alone don't reveal
`N` without already knowing it.

**Partial, indirect signal (not conclusive):** extracted `p`/`q` from *our own* issued leaf's
private key (`openssl rsa -text`) — both are proper ~1024-bit primes with `|p-q|` also ~1023 bits
(no Fermat-close-primes weakness, no small factors, looks like healthy `os.urandom`-backed
generation). This doesn't prove the **CA's own** key is equally strong (it could've been generated
by different, older tooling — CAs are often long-lived/manually-created vs. per-request leaf
keygen), but it does mean **the leaf-issuance code path shows no evidence of a systemic weak-RNG
bug** that would make us confident the CA key is weak too.

### 2.3 Admin CN check: exact, and — new finding — enforced only at the app layer, only on `/`

Presented our real, valid, BeeCA-chain-verified leaf (wrong CN) to the admin host:

```
$ curl -i --cert cert_0.pem --key key_0.pem https://admin-bv5kavo6.beeca.avitoctf.ru/
HTTP/1.1 403 FORBIDDEN
Сертификат подлинный и выпущен этим ульем (CN='shadowklesh@gmail.com'), но прав администратора
недостаточно: требуется CN=admin.
```

This is the third differential CRYPTO_NOTES.md flagged as untested — now confirmed. Key new
findings from probing around it (all with the valid cert attached):

- **nginx's mTLS gate is server-wide but coarse**: it only checks "is there a chain-valid BeeCA
  cert at all" (`$ssl_client_verify == SUCCESS`), for every path, every method. With **no** cert,
  literally every path (`/health`, `/admin`, `/.env`, anything) gets the generic
  "требуется клиентский сертификат BeeCA" 403 — confirming the earlier finding that this part is
  server-block-wide.
- **The `CN == admin` check, however, is application-level and scoped only to the `/` route.**
  With a *valid* cert but wrong CN: `/` gives the dynamic "insufficient rights" message above, but
  **every other path** (`/admin`, `/prompt`, `/first-prompt`, `/system_prompt`, `/queen`,
  `/static/*`, `/favicon.ico`, `/robots.txt`, `/index.html`, `/промпт`/`/первопромпт` (Cyrillic),
  etc. — ~25 tried) returns a **plain Flask 404**, not the CN-mismatch message. This proves those
  routes genuinely don't exist in the app (not "exist but gated") — there's no secondary
  unprotected route serving the same content.
- Method fuzz on `/` (valid cert, wrong CN): `GET`→403 (app check), `HEAD`→403, `OPTIONS`→200
  (empty, likely unguarded CORS-preflight-style handler), `POST/PUT/DELETE/PATCH`→405 Method Not
  Allowed (routing-level, before any CN check — consistent with a `methods=['GET','HEAD']` Flask
  route). No method bypasses the CN check for `GET`.
- Path-normalization variants (`//`, `/.`, `/./` , `/?x=1`) still hit the same CN-checked `/`
  handler (Flask/Werkzeug normalizes these to the same route) — `/%2e`, `/index`, `/root` genuinely
  404 (different routes entirely, don't exist).
- Re-tested every previously-tried header-injection trick (`X-SSL-Client-CN: admin`,
  `X-Forwarded-Client-Cert`, `X-Client-Cert-CN`, `X-SSL-CLIENT-S-DN`, etc.) **this time while
  presenting our valid cert** (prior tests in CRYPTO_NOTES §3 only tried these with *no* cert at
  all, so they never reached the app's real "check CN" code path to begin with). **Still no
  effect** — the app reads only the genuine nginx-injected `$ssl_client_s_dn_cn`, headers are fully
  ignored regardless of cert-presence state. Closes this off for good, in the strongest form of the
  test.
- Bonus: `Host: certissue-bv5kavo6.internal` while SNI'd to the admin domain, **with the valid
  cert attached**, still falls through to the portal SPA fallback (re-confirms the vhost-confusion
  bug from CRYPTO_NOTES §4 one more time, no new capability).

**Conclusion: the CN check is a straightforward, correctly-scoped exact-match (`cn == "admin"`)
done once, server-side, off the real TLS-verified subject — no header/method/path bypass exists.**

## Where this leaves us — no flag, and why

To get `CN=admin` we would need one of:
1. **Control CN at enroll time** — closed. CN = the verified Google account's full email, verbatim,
   with zero server-side override surface (confirmed exhaustively across both this pass and prior
   passes, including via the internal-trust endpoint which also ignores `cn=` params).
2. **A sub-CA/self-signing bug** — closed (§2.1, `CA:FALSE` + no `keyCertSign`).
3. **A weak/factorable CA key** — **untestable**, because the CA certificate itself is not exposed
   anywhere reachable (§2.2), despite an exhaustive path/subdomain/port/format sweep across all
   three known vhosts.
4. **Hijack/approve an existing `admin` enrollment via the internal-issuer bug** — the bug is real
   and unauthenticated (§ Frontier 1), but requires a known `uuid`; admin's cert is already
   `issued` (per the challenge's own framing — "only the IT-lead has one"), not `pending`, so
   there's nothing to approve even if the uuid were known; and uuids are genuine random UUIDv4
   (122 bits), unenumerable (no listing endpoint exists anywhere, confirmed again this pass).
5. **A CN-check bypass at the admin host** — closed (§2.3): exact match, app-level, no
   header/method/path/vhost-confusion bypass survives with a valid cert attached.

**Single best remaining lead, unverified:** none of the avenues explicitly assigned to this pass
panned out to a flag. The only structurally-open question left is whether the admin's own
`private_key_pem` (recall: **the server hands back the raw private key in the `/api/enroll` JSON
response** — a real design smell) could be recovered through some *other* part of the CTF (e.g. an
unrelated RCE/file-read on this same box, out of BeeCA's own scope) — if the admin's enrollment was
minted the same way, its key was generated server-side and briefly transited the wire in the same
insecure fashion ours did. That's speculative and outside this challenge's own attack surface as
mapped so far.

## Artifacts

- `/Users/mmk/github/avitoctf2026/beeca/artifacts/beeca-client.p12` — real, valid, CA-signed p12
  for `cn=shadowklesh@gmail.com` (password `beeca`), obtained via the Frontier-1 self-approve bug.
- `/Users/mmk/github/avitoctf2026/beeca/artifacts/cert_0.pem`, `key_0.pem` — split leaf cert/key.
- `/Users/mmk/github/avitoctf2026/beeca/artifacts/admin_sclient_v2.txt` — fresh TLS dump of the
  admin host's `CertificateRequest`.
- Enrollment state left `status:"issued"` (not left `declined` from the decline/re-approve test
  cycle) — participant's cookie still works, cert still downloadable.

**No `FLAG.txt` written — CN=admin was not achieved this pass.**

---

## ADDENDUM (later pass) — verdict: is a SECOND BeeCA-signed cert obtainable without a 2nd Google account?

Context: the deterministic-keygen crack (`DETKEY_CRACK_NOTES.md`) was refuted (~230K candidates, no
signal), so the GCD-of-two-leaves CA-key-recovery plan (`recover_ca_and_forge.py`, this file's
Frontier 1/2 above) became the primary path — but it needs a **second, distinct BeeCA-signed leaf**,
and we only have one (`leaf.crt`/`leaf.key`, `cn=shadowklesh@gmail.com`, serial `1000`=4096). This
pass exhaustively re-checked all three ways to get a second signed cert **without** a second Google
login. **Verdict: all three are dead/blocked.** Live connectivity confirmed throughout (portal 200,
admin 403-no-cert, internal issuer 200 via `--resolve`).

### 1. The CA cert itself (would give N directly, no GCD needed) — DEAD, re-confirmed
Swept ~40 paths (`/ca`, `/ca.crt`, `/ca.pem`, `/BeeCA.crt`, `/beeca-ca.crt`, `/cacert.pem`,
`/pki/ca.crt`, `/root-ca.pem`, `/roots.pem`, `/api/ca`, `/internal/ca*`, `/internal/root*`,
`/.well-known/ca.crt`, `/crl*`, `/chain.pem`, `/fullchain.pem`, `/intermediate.pem`, bee-themed
guesses, etc.) against **all three** vhosts (portal — no cert; admin — with `leaf.crt`/`leaf.key`;
internal issuer via `--resolve` — with and without our client cert). Only hits were `/internal/*` on
the **portal** vhost returning `403` (the known nginx path-prefix block on that specific vhost, not a
real route — matches Frontier-1 notes above, not new). Nothing on admin or the internal issuer.
Also re-probed `/internal/cert?uuid=<ours>&action=approve` with extra params designed to coax a
chain/CA back (`chain=1`, `include_ca=1`, `format=chain`, `format=pem`, `with_ca=true`,
`return=full`) — response is **always** the bare `{"ok":true,"status":"issued","uuid":...}`, no
extra fields, regardless of params (extra params are silently ignored, confirmed again). Confirmed
`GET` and `POST` behave identically on `/internal/cert` (matches `FRESHEYES_NOTES.md`'s CSRF-able
finding). Tried all plausible **read-style** `action` values (`status`,`info`,`get`,`view`,`show`,
`details`,`fetch`,`read`,`list`,`query`,`lookup`) — every one rejected with the same
`"action must be approve or decline"` string; the endpoint genuinely cannot read/echo anything, only
mutate approve/decline state. Re-dumped our leaf's x509 extensions: `Basic Constraints: CA:FALSE`
(critical), `Key Usage: Digital Signature` (critical), `EKU: TLS Web Client Authentication` — **no
AIA, no CRL Distribution Points, no OCSP** — no chain-leak side channel of any kind on the leaf
itself. TLS `CertificateRequest` on the admin host remains DN-only by spec (`CN=BeeCA, O=BeeCA`),
structurally cannot leak modulus. **The CA cert is not reachable from any endpoint we can find.**

### 2. The admin's public `CN=admin` cert (download-by-id / IDOR) — DEAD, re-confirmed
- `GET /api/cert` (the only cert-download route anywhere) returns `401 {"error":"unauthorized"}`
  **unconditionally without a valid session cookie** — tested bare, with `?uuid=<our known uuid>`
  (IDOR probe — still 401, uuid param has zero effect on the auth gate), and with our client cert
  presented via mTLS (`--cert leaf.crt --key leaf.key`) on both the portal and the internal-issuer
  vhost — **still 401 both times**. Confirmed separately that presenting the client cert does **not**
  bootstrap a session at all: `GET /api/me` with the cert attached still returns
  `{"authenticated":false}` on both portal and internal-issuer hosts. Auth here is purely
  `beeca_session` cookie-based (name recovered from `recover_ca_and_forge.py`'s own comments); mTLS
  and session are two fully independent, non-interacting trust mechanisms in this app.
- No listing/enumeration endpoint exists anywhere (re-confirmed; this pass only re-verified the
  negative, the exhaustive path fuzz was already done in Frontier 1 above). uuids are genuine random
  UUIDv4 (122 bits) — unenumerable even if a listing bug existed elsewhere.
- Checked for a pre-login session-fixation cookie (anonymous `GET /` on the portal, looking for any
  `Set-Cookie` we could later "upgrade" via login) — **none is set**; the portal issues no cookie at
  all until a real OAuth callback completes. No fixation vector.
- **Net: there is no way to fetch ANY cert bytes — ours, the admin's, or anyone's — without a live,
  real-Google-login-derived `beeca_session` cookie.** This closes the IDOR/download angle completely.

### 3. Re-signing a SECOND cert for our OWN account (decline → approve cycle) — UNTESTABLE, not closed
This is the one item that isn't a clean "no": `/internal/cert` approve/decline is genuinely
unauthenticated and would happily execute a `decline` then `approve` on our own known uuid
(`05e4cb4f-c01f-41f5-ab31-35179065ef52`) right now. **But** the only way to retrieve the resulting
cert bytes to check whether the signature/serial/validity actually changed is `GET /api/cert`, which
—per item 2 above— requires the `beeca_session` cookie, and **we do not have one** (it was captured
by a different, earlier agent pass in a session that has since expired; no cookie jar was preserved
in this repo, confirmed by search; the client cert does not substitute for it; there is no
session-fixation path to mint one without a real Google login). **I deliberately did not execute the
decline/approve cycle blind** — with no way to observe or extract any result, it would be pure risk
(potentially disturbing our only currently-working, verified `issued` credential) for zero
information gain. If a fresh session cookie becomes available (would require an actual completed
Google OAuth login for `shadowklesh@gmail.com`, e.g. from a human with browser access), this specific
test — decline, re-approve via the unauthenticated internal endpoint, then diff the freshly
downloaded `p12`'s serial/validity/signature bytes against our saved `leaf.crt` — is cheap and should
be run then; it's the only one of the three items that isn't definitively dead, just currently
unreachable.

### Overall verdict
**BeeCA is blocked on obtaining a second BeeCA-signed certificate by any means that doesn't require a
second real Google OAuth login.** All CA-cert-exposure and IDOR/download avenues are exhaustively
closed (items 1–2). The one remaining open question (item 3, re-signing our own account) needs a live
session we don't currently have and can't forge or fixate. Recommend: either get a human to complete
a second Google login (throwaway account, per `FRESHEYES_NOTES.md`'s plan) to produce leaf₂ for the
GCD attack, or get a fresh session cookie for the *existing* account to at least run the cheap
decline/approve re-sign test before concluding item 3 is dead too.
