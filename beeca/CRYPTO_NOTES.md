# BeeCA — CRYPTO / mTLS / CA lane notes

Scope: certificate system, CA weaknesses, mTLS CN-matching at `admin-bv5kavo6.beeca.avitoctf.ru`.
Web/logic lane (feedback XSS, enroll flow, OAuth) is `WEBLOGIC_NOTES.md` — read that first, we
share one blocker (see "Shared blocker" below).

All commands below were run live against the sanctioned CTF instances. Raw `openssl s_client`
output saved at `/Users/mmk/github/avitoctf2026/beeca/artifacts/admin_sclient.txt`.

## 1. Admin host TLS layer facts (confirmed)

```
$ echo | openssl s_client -connect admin-bv5kavo6.beeca.avitoctf.ru:443 -showcerts \
    -servername admin-bv5kavo6.beeca.avitoctf.ru
```

- Server cert presented for the handshake is the ordinary **Google Trust Services** wildcard
  `CN=*.beeca.avitoctf.ru` (issued by `WR1` ← `GTS Root R1` ← `GlobalSign Root CA`, RSA 2048,
  sha256WithRSAEncryption). This is just the outer TLS transport cert — irrelevant to client-cert
  trust, but confirms `portal-*` and `admin-*` are served off the **same wildcard cert / same
  physical nginx**, since both resolve to the same IP:

  ```
  $ dig +short admin-bv5kavo6.beeca.avitoctf.ru   -> 93.77.163.176
  $ dig +short portal-bv5kavo6.beeca.avitoctf.ru  -> 93.77.163.176
  ```

- The `CertificateRequest` TLS message (both TLS1.2 and TLS1.3 tested) leaks the trusted CA:

  ```
  Acceptable client certificate CA names
  CN=BeeCA, O=BeeCA
  Client Certificate Types: RSA sign, DSA sign, ECDSA sign
  ```

  **Only one CA is trusted, subject exactly `CN=BeeCA, O=BeeCA`** (no OU, no C). This is the CA
  the portal's issued `beeca-client.p12` must chain to.

- TLS handshake **completes successfully with zero client certificates presented** (`Verify
  return code: 0 (ok)`, full HTTP response received) — i.e. `ssl_verify_client` on this vhost is
  **not** the hard `on` mode (which aborts the handshake for bad/missing certs at the TLS layer);
  it behaves like `optional`/`optional_no_ca` with the actual accept/reject decision made after
  the handshake, using `$ssl_client_verify` (see §2). This matters because `optional_no_ca` is a
  classic nginx footgun (accepts *any* client cert, even self-signed/wrong-CA, and trusts the app
  to check `$ssl_client_verify==SUCCESS`) — tested and ruled out in §2.

## 2. mTLS 403 response differential (three distinct code paths, confirmed)

| Client cert presented | Response |
|---|---|
| none | `403 text/plain`: `Для доступа требуется клиентский сертификат BeeCA.` (`Connection: close`) |
| self-signed `CN=admin` (own key, own issuer, **not** chained to `CN=BeeCA,O=BeeCA`) | `403 text/plain`: `Клиентский сертификат не прошёл TLS-проверку.` (different message, `Connection: close`) |
| *(untested — need a real BeeCA-signed leaf)* | expected: either success or a third distinct "wrong CN" message |

Repro:
```
$ openssl req -x509 -newkey rsa:2048 -keyout selfsigned_admin.key -out selfsigned_admin.crt \
    -days 2 -nodes -subj "/CN=admin"
$ curl -i --cert selfsigned_admin.crt --key selfsigned_admin.key \
    https://admin-bv5kavo6.beeca.avitoctf.ru/
HTTP/1.1 403 Forbidden
Клиентский сертификат не прошёл TLS-проверку.
```

**Conclusion: the naive "self-signed CN=admin bypass" does NOT work.** The server genuinely
validates the presented cert's signature chain against the trusted `CN=BeeCA,O=BeeCA` CA before
ever looking at the subject/CN. `optional_no_ca` is ruled out — this is a properly-configured
`ssl_verify_client optional` (or `on` with a custom error_page) doing real chain validation, with
app/nginx-level string differentiation only *after* a chain-valid cert is presented. This closes
off items 3's "trivial" sub-cases (parsing differentials on subject fields only matter once we
have a **validly-chained** cert to manipulate — we don't have one yet, see blocker below).

## 3. Header-injection bypass attempts — all failed (good hygiene)

Tried spoofing every plausible nginx→app trust header, no client cert, against
`admin-bv5kavo6.beeca.avitoctf.ru/`:
`X-SSL-Client-CN: admin`, `X-Ssl-Client-Verify: SUCCESS`, `ssl-client-cn: admin`,
`X-Forwarded-Client-Cert: CN=admin`, `X-Client-Cert-CN: admin`, `X-SSL-CLIENT-S-DN: CN=admin,O=BeeCA`
(individually and combined). **All still `403` with the "no cert" message.** The app is reading
real `$ssl_client_*` connection variables set directly by nginx from the TLS handshake, not
attacker-controllable request headers — no smuggling vector here.

Also tried generic path bypasses on the admin vhost (`//`, `/../`, `/health`, `/status`,
`/robots.txt`, `/api`, `/.git/config`, etc.) — **all uniformly `403`**, the mTLS check is applied
at a `server{}`-wide level (or in a very generic `location /`), not scoped to specific routes.

## 4. Host-header / SNI vhost-confusion (found a real bug, but it's a dead end)

Since `admin-bv5kavo6` and `portal-bv5kavo6` share one IP, tried decoupling the TLS SNI (fixed by
the curl URL) from the HTTP `Host` header:

```
$ curl -i -H "Host: certissue-bv5kavo6.internal" https://admin-bv5kavo6.beeca.avitoctf.ru/
HTTP/1.1 200 OK
Content-Disposition: inline; filename=index.html
<!doctype html> ... <title>Улей — портал сертификатов</title> ...   # the PORTAL's SPA shell

$ curl -H "Host: certissue-bv5kavo6.internal" https://admin-bv5kavo6.beeca.avitoctf.ru/api/me
{"authenticated":false}                                             # live backend, portal's API
```

**Confirmed bug**: any `Host` header that doesn't exactly match a configured `server_name`
(`admin-bv5kavo6.beeca.avitoctf.ru` or `portal-bv5kavo6.beeca.avitoctf.ru`) falls through to an
nginx `default_server` on the *same listener* that has **no mTLS requirement at all** and proxies
to the same backend app the portal uses. This completely sidesteps the "client cert required"
wall — but:

- It only reaches the **portal** backend (same `/api/me`, `/api/feedback` — verified live, see
  below), not a separate protected "admin" application. There is no distinct admin backend
  reachable this way.
- `/internal/cert` (the operator approve/decline endpoint) is nginx-blocked with an explicit
  `403 Forbidden` (bare nginx page) when `Host` correctly matches `portal-bv5kavo6...`, **but**
  under the Host-spoofed `default_server` path it instead returns an **app-level** `404 text/plain
  "not found"` (9 bytes) — i.e. the fallback backend process genuinely has no `/internal/cert`
  route registered; it isn't just nginx-denied there, the route doesn't exist in this process at
  all. Confirmed identical on both `portal-bv5kavo6` and `admin-bv5kavo6` SNI with the same
  spoofed Host — it's the same backend either way.
- Sending the *other* real hostname explicitly (`Host: portal-bv5kavo6.beeca.avitoctf.ru` while
  connecting/SNI-ing to the admin IP) gives a **third** behavior: generic stock nginx
  `403 Forbidden` — suggests an explicit deny rule keyed on that literal known hostname to close
  the "obvious" cross-vhost attempt, while the catch-all `default_server` case was left open.

Net effect: this is a genuine nginx vhost-isolation flaw (worth reporting/fixing) and it does
prove the internal `/internal/cert` route lives on a **separate process/service** not reachable
via this default vhost — but it does **not** get us past the mTLS wall to the actual protected
"Первопромpt" content, and does **not** provide a new capability we didn't already have via the
portal's normal hostname. Verified this settles WEBLOGIC_NOTES.md §5's open TODO with a definitive
negative result (their exact repro command reproduced above with matching output).

## 5. No public CA bundle / CRL / internal-DNS leak

- Probed `/ca.crt`, `/ca.pem`, `/BeeCA.crt`, `/beeca-ca.crt`, `/static/ca.crt`, `/pki/ca.crt`,
  `/crl.pem`, `/root.crt`, `/.well-known/ca.crt` on both portal and admin hosts — all `404`
  (portal) / `403` (admin, mTLS wall still applies to arbitrary paths there). No CA certificate or
  CRL is served anywhere in the public web surface.
- `certissue-bv5kavo6.internal` does **not** resolve from the public internet (`NXDOMAIN`),
  confirming it's a genuinely intranet-only name, consistent with RECON.md.
- `oauth.beeca.avitoctf.ru` root is a plain `404` (only the callback path exists); its OAuth
  `state` param is a self-contained `HS256`-signed JWT
  (`{nonce, origin, iat, exp:+10min, iss:"beeca-app", aud:"beeca-oauth-state"}`). It's already
  HS256 (no RS256→HS256 alg-confusion angle — nothing to confuse it with), and even a perfectly
  forged `state` doesn't bypass login: `/oauth2/callback` still needs a real Google-issued `code`,
  exchanged server-side with a `client_secret` we don't have. **Ruled out** as a login-bypass
  vector; not pursuing further (flagged by web lane too, resolved here).

## 6. Shared blocker with the web/logic lane

**We cannot obtain an actual BeeCA-issued client certificate without a real, completed Google
OAuth login** (`GET /login` → real `accounts.google.com` with a real `client_id`, real consent
screen, real code exchange). This agent has no browser and no real Google account credentials, and
there is no bypass, backdoor, debug header, or forgeable-state shortcut found anywhere in the
public surface (§3, §5 above; web lane independently confirms the same in `WEBLOGIC_NOTES.md` §1/§3).

**This is a hard stop for the rest of the crypto lane's task list** (dumping the CA's real
sigalg/key size/serial policy/extensions, checking `BasicConstraints`/`pathLen` on the issued leaf
for a sub-CA-abuse attack, and testing CN-matching differentials — multi-CN RDNs, RDN order,
PrintableString vs UTF8String, embedded `CN=admin` in another field — against the live admin
endpoint) **all require an actual signed leaf certificate to start from.**

### Leading hypothesis for the real vuln (needs the p12 to confirm/deny)

Given the challenge is literally named "**BeeCA**" and is tagged Hard/0-solves, the most likely
intended crypto bug — once we have a real issued leaf — is a **missing/wrong `BasicConstraints`
on the issued client leaf** (e.g. no `CA:FALSE`, or `CA:TRUE` with no `pathlen` restriction, or a
key usage that includes `keyCertSign`). If the CA lets an ordinary enrolled user's leaf act as an
intermediate, we could self-sign a new `CN=admin` certificate with our own leaf's private key,
chaining leaf→BeeCA root, and the admin host's TLS chain-validation (confirmed strict in §2) would
accept it as long as the chain path is cryptographically valid to the trusted root — nginx doesn't
enforce `pathlen`/`CA:TRUE` on intermediates unless explicitly configured to. Secondary
hypotheses to check once we have a cert: predictable serial numbers (sequential/timestamp-based,
visible in the enroll response `{serial, cn, status}`), and RSA key size (if the CA issues small
RSA leaves, e.g. 512/768-bit, they may be factorable — but this is speculative, no key material
observed yet).

## Next concrete step (unblocks both lanes)

A human needs to, in a real browser:
1. Visit `https://portal-bv5kavo6.beeca.avitoctf.ru/`, click "Начать вход" / log in with a real
   Google account.
2. Click "Запросить сертификат" (may land on `pending` needing moderator approval — see
   `WEBLOGIC_NOTES.md` for the feedback/approval angle).
3. Once status is `issued`, click "Скачать .p12" and hand `beeca-client.p12` (password `beeca`) to
   this lane, or hand over the authenticated session cookie so this lane can drive `/api/enroll`
   and `/api/cert` directly.

Once we have it, immediate next actions queued:
```
openssl pkcs12 -info -in beeca-client.p12 -passin pass:beeca -nodes
openssl x509 -in <leaf>.pem -text -noout        # subject, issuer, serial, sigalg, validity,
                                                  # EKU/KU/SAN/BasicConstraints, key size
openssl x509 -in <ca>.pem   -text -noout        # same for the CA cert in the chain
# then: BasicConstraints/pathlen sub-CA test, serial predictability, CN-differential crafting
# against https://admin-bv5kavo6.beeca.avitoctf.ru/ with --cert/--key
```

## Status: BLOCKED, no flag yet

No weakness has been confirmed *exploitable* yet (self-signed bypass ruled out, header-injection
ruled out, vhost-confusion found but dead-ends, OAuth-state forgery ruled out as a login bypass).
The CA/PKI-specific analysis (the actual likely vuln class) cannot proceed further without a real
issued certificate. `FLAG.txt` not written.
