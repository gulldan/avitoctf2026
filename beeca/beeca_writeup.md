# BeeCA — write-up

**Flag:** `avito{uZUzUlEy_WeaK_CrYp7O_vIBeee}`
**Class:** Crypto + Web + Logic · **Difficulty:** Hard · **Points:** 1000 · **Teams solved:** 0
**Author:** @v1ru55, SPbCTF

**One-paragraph story of the solve.** The prize (the "Первопромпт" / First Prompt) lives behind an
mTLS wall that only opens for a client certificate whose subject is exactly `CN=admin`. You can only
get certificates named after *your own* verified Google email, and the naive "self-sign a CN=admin
cert" is rejected because the wall does real chain validation. So the whole challenge is: **how do
you obtain a certificate the BeeCA certificate authority never intended to issue?** The answer is a
three-bug chain — (1) an *unauthenticated* internal issuer endpoint lets us instantly self-approve
enrollments, (2) a decline-and-re-enroll logic flaw lets us mint **two** distinct CA-signed leaves
from a single account, and (3) two signatures are enough to algebraically **recover the CA's public
modulus `N` from the signatures themselves** — even at `e=65537` — after which the hand-rolled CA
key factors instantly and we forge our own `CN=admin` cert.

---

## 1. The challenge

> "Badgers found infrastructure built by a swarm of *vibecoder bees*."

- **Portal** `portal-bv5kavo6.beeca.avitoctf.ru` — a React/Vite SPA that issues **named client
  certificates**. You log in with Google, request a cert, and (after approval) download a
  `beeca-client.p12`. The certificate's `CN` is your verified email.
- **Admin host** `admin-bv5kavo6.beeca.avitoctf.ru` — serves the *Первопромпт* and is reachable
  **only** with a client certificate whose `CN=admin`. Only the "IT-lead bee" has one.
- **Goal:** present a `CN=admin` certificate to the admin host and read the First Prompt (which ends
  with the flag).

The three category tags (Crypto + Web + Logic) are a strong hint up front: the solution is a chain,
not a single trick.

## 2. Recon — mapping the certificate system

**Portal API** (recovered from the minified bundle `portal.js` / `/static/assets/index-*.js`):

| Endpoint | What it does |
|---|---|
| `GET /api/me` | session state: `{authenticated, email, enrollment:{uuid, cn, status, serial}}` |
| `POST /api/enroll` | creates/returns an enrollment. **`CN` = your verified SSO email, verbatim.** Keypair is generated **server-side** — the JSON response even hands back `private_key_pem`. Status starts `pending` (needs operator approval). Calling it again on an existing `pending`/`issued` enrollment returns the **same** persisted record (idempotent), not a new one. |
| `GET /api/cert` | once `issued`, downloads `beeca-client.p12` (password `beeca`) |
| `POST /api/feedback` | "speed up my review"; a moderator supposedly reads it |
| `GET /login`, `POST /logout` | real Google OAuth2 |
| `POST /internal/cert?uuid=&action=approve\|decline` | the **operator** approve/decline action — lives on an *internal* host |

The session is an **HS256 JWT**. We attacked it hard (rockyou + masks ≤7 alnum + themed guesses for
the secret; `alg:none`/`None`/empty-key confusion; `jwk`/`jku`/`kid` header injection) — **all
rejected**. The JWT is genuinely unforgeable, so we cannot mint an arbitrary-email session. That
matters because it means we cannot simply log in "as admin".

**The admin host's mTLS gate**, probed with `openssl s_client` (raw dumps in `artifacts/`):

- The TLS `CertificateRequest` message leaks the trusted CA's subject: **`CN=BeeCA, O=BeeCA`** — the
  *only* CA accepted. Any client cert we present must chain to it.
- The gate does **real chain validation** first, then an **exact `CN == "admin"`** check in the app.
  Three distinct 403 responses prove all three code paths exist:

  | Cert presented | Response |
  |---|---|
  | none | `Для доступа требуется клиентский сертификат BeeCA.` (mTLS layer, `Connection: close`) |
  | self-signed `CN=admin` (not chained to BeeCA) | `Клиентский сертификат не прошёл TLS-проверку.` (chain validation failed) |
  | valid BeeCA leaf, wrong CN | `Сертификат подлинный … (CN='shadowklesh@gmail.com'), но прав администратора недостаточно: требуется CN=admin.` |

That third message is the key oracle: a **validly-chained** cert reaches the app, and the app
demands `CN` *exactly* equal to `admin`.

**Facts confirmed by direct testing (not yet a working plan, just the map):**

- Enroll **ignores** any client-supplied `cn`/`email`/`subject`/`name` (query, JSON body, or
  `X-Forwarded-Email` header) — CN is strictly the SSO email.
- The issued leaf is `BasicConstraints: CA:FALSE (critical)` + `KeyUsage: Digital Signature` only,
  EKU `clientAuth`.
- `/api/feedback` is a latency-flat async **log sink**.
- Header spoofing (`X-SSL-Client-CN: admin`, `X-Forwarded-Client-Cert`, `X-SSL-CLIENT-S-DN`, …) is
  ignored — the app reads the genuine nginx `$ssl_client_s_dn_cn`, not request headers.
- The **CA certificate is not downloadable anywhere** (swept ~40 paths / subdomains / ports on all
  three vhosts; `.p12` and `/api/cert` are leaf-only, no chain param works).

Recon conclusion: we can't rename our cert, can't forge the session, and can't download the CA
directly. Whatever the real bug is, it has to turn these individually-solid-looking facts into a
chain. That framing drove the rest of the solve — detailed thread-by-thread in §3.

## 3. How we got there (hypothesis logic)

This challenge took the longest not because any single step was hard, but because **several
plausible-looking bugs turned out to be dead ends**, and the actual chain only became visible after
closing all of them. Six threads, in the order they were actually run down:

### Thread A — can we just *become* admin without exploiting anything?

- **Observation.** `enroll` returns whatever the SSO layer hands it; nothing in the request body
  controls `cn`.
- **Hypothesis.** Maybe some SSO edge case (display name, local-part-only email, a `+admin` alias,
  an unverified secondary email) lets the returned `cn` be something other than the full verified
  address.
- **Test.** Did a real Google OAuth2 login and inspected the resulting `/api/me`/enroll record.
- **Result — dead end.** `cn` came back as the **full verified email, verbatim**
  (`shadowklesh@gmail.com`). You cannot register a real Google account whose email is literally
  `admin` without owning/verifying a domain (a real-world cost, not a request-crafting trick). CN
  control via SSO identity is closed.
- **Also tried and refuted in the same pass:** JWT secret brute force (rockyou + themed masks),
  `alg:none`, `jwk`/`jku` header injection, every plausible spoofable header
  (`X-SSL-Client-CN`, `X-Forwarded-Client-Cert`, …). All rejected — the app trusts only nginx's own
  `$ssl_client_s_dn_cn`, and the JWT is genuinely unforgeable from outside.

### Thread B — is there a sub-CA / self-signing path?

- **Observation.** `POST /api/enroll` hands back `private_key_pem` for our own leaf.
- **Hypothesis.** If the issued certificate had `BasicConstraints: CA:TRUE` (or a permissive
  `pathlen`), we could use our own already-issued leaf as an intermediate and self-sign a fresh
  `CN=admin` certificate — no CA compromise needed at all.
- **Test.** Parsed our own leaf's X.509 extensions.
- **Result — dead end.** `BasicConstraints: CA:FALSE (critical)`, `KeyUsage: digitalSignature` only,
  `EKU: clientAuth`. The issuer correctly marks every leaf as a pure end-entity cert; it cannot sign
  anything. No sub-CA trick is available.

### Thread C — can we just get the CA cert/key directly?

- **Observation.** Self-hosted PKI demos frequently leak the CA bundle somewhere (a static path, a
  CRL distribution point, an internal DNS record, a debug endpoint).
- **Hypothesis.** The CA cert (or, better, the CA key) might be reachable by URL-guessing across all
  three vhosts and a handful of ports.
- **Test.** Swept ~40 candidate paths/subdomains/ports (`/ca.crt`, `/ca-bundle.pem`, `/.well-known/`,
  chain params on `/api/cert`, CRL/OCSP paths, etc.) on `portal-`, `admin-`, and any discovered
  internal hosts.
- **Result — dead end.** Nothing found anywhere. This was actually useful information: it told us N
  would have to be **recovered**, not read off disk, which is what pointed the crypto lane at
  signature-based recovery in Thread F.

### Thread D — nginx Host/SNI confusion (a real bug, but not *the* bug)

- **Observation.** `admin-bv5kavo6` and `portal-bv5kavo6` resolve to the **same IP**
  (`93.77.163.176`). nginx typically selects a `server{}` block by SNI, and some setups only check
  `Host` loosely against it.
- **Hypothesis.** Sending a mismatched `Host` header while SNI-connecting to the admin vhost might
  route us into a different, less-protected backend — possibly one that skips the mTLS check.
- **Test.** `curl -H "Host: certissue-bv5kavo6.internal" https://admin-bv5kavo6.beeca.avitoctf.ru/`
  and variants (including the literal other real hostname as `Host`).
- **Result — real bug, but a dead end for reaching admin content.** An unrecognized `Host` value
  *does* fall through to an nginx `default_server` with **no mTLS requirement at all** — but it only
  proxies to the same **portal** backend (`/api/me`, `/api/feedback`), not a separate admin
  application, and `/internal/cert` isn't registered on that backend process at all (a clean
  app-level 404, not an nginx block) — proving the internal issuer lives on a genuinely different
  service. Sending the *other* real hostname explicitly gets a **third** behavior: a hardcoded nginx
  `403`, i.e. an explicit deny rule for the known name while the catch-all fallback was left open.
  Net effect: interesting nginx hygiene bug, zero new capability toward `CN=admin` — **but it planted
  the idea that plays out in Thread E**: several *named* services clearly share this one edge IP,
  they're just routed by name.

### Thread E — Bug 1: the internal issuer, reached by SNI+Host together

- **Observation.** The bundle references an internal host name,
  `certissue-bv5kavo6.internal`, that does not resolve publicly. Thread D already showed this IP
  hosts multiple named vhosts selected by SNI/Host.
  ```
  $ dig +short admin-bv5kavo6.beeca.avitoctf.ru    # 93.77.163.176
  $ dig +short portal-bv5kavo6.beeca.avitoctf.ru   # 93.77.163.176  (same IP)
  ```
- **Hypothesis.** If `certissue-bv5kavo6.internal` is "protected" purely by not being in public DNS,
  and it's colocated on the same edge IP as everything else, then forcing **both** the TLS SNI and
  the HTTP `Host` to that name should route us straight to it — no auth needed, since "internal"
  here means "not advertised," not "network-isolated."
- **Why the earlier bare `-H "Host:"` attempt (Thread D) wasn't enough:** that only overrode the
  `Host` header while SNI stayed on the admin/portal name, which nginx used to pick the vhost — you
  need `--resolve` (or equivalent) so the **TLS handshake itself** claims to be
  `certissue-bv5kavo6.internal`, matching Host.
- **Test.**
  ```bash
  curl -sk -X POST \
    --resolve certissue-bv5kavo6.internal:443:93.77.163.176 \
    "https://certissue-bv5kavo6.internal/internal/cert?uuid=<UUID>&action=approve"
  ```
- **Confirmed.** `{"ok":true,"status":"issued","uuid":"<UUID>"}` — **zero authentication, zero
  client cert.** We fully characterized it: `action` is a strict `approve|decline` enum, `uuid` must
  reference an existing enrollment (random UUIDs → `not found`), every override param (`cn`,
  `email`, …) is silently ignored, no other route exists on this host. It doesn't let us *rename* a
  cert — but it lets us **instantly self-approve any enrollment we create**, collapsing the
  multi-minute human-review delay to seconds. That speed is exactly what Thread F needs.

> Segmentation-by-obscurity is not segmentation: an "internal only" service that shares an edge IP is
> one matching `SNI`/`Host` away.

### Thread F — the deterministic-keygen rabbit hole, then the real Bug 2

- **Observation.** Calling `/api/enroll` twice in the same session returned a **byte-identical**
  `private_key_pem` both times.
- **Hypothesis (the expensive one).** Read literally, "same input → same private key" smells like a
  vibecoded RSA keygen seeded deterministically from the CN — i.e. the keypair is
  `f(CN)` for some guessable `f`. If true, `admin`'s private key is just `f("admin")`, no CA
  compromise needed at all. This looked *extremely* promising: the server handing back
  `private_key_pem` at all is already an unusual design choice, consistent with a hand-rolled,
  possibly-seeded keygen.
- **Test.** A dedicated crack pass threw **~230,000 candidate derivations** at the real leaf's known
  `(p, q)`: paired sequential PRNG draws (`random.Random(seed)`, hashlib-CTR, `getPrime` /
  `sympy.nextprime` in various framings) across 46 seed-material variants; a decoupled
  single-target search (any formula landing on *either* p or q) across 134 seed materials ×
  multiple expansion methods (18,441 candidates); UUID-focused sweeps exploiting the UUID's cheaper
  128-bit-equality oracle (76,325 + 105 candidates, including HKDF/AES-CTR-DRBG/ChaCha20
  constructions); and — the decisive diagnostic — a **near-miss ranking** of ~10,000 candidates by
  shared-prefix bit-length against the real primes, to catch a formula that's "correct in spirit"
  but slightly off.
- **Result — refuted, and here's why it looked true.** Zero exact matches, and the near-miss ranking
  found **no signal above pure-chance noise** (best hit: 13 shared bits, exactly
  `log2(10000)` — the expected value for random guessing). A statistical check of the real `(p, q)`
  (bit-balance, longest run, byte-repeat distribution) was consistent with genuine `os.urandom`.
  Cross-checking against other recon passes revealed the simpler explanation: **`/api/enroll` is
  idempotent** — it persists one record per account and returns that same stored record (including
  its already-generated key) on every repeat call. "Two enrolls, same key" was never evidence of a
  seed formula; it was just an ordinary idempotent API returning the same DB row twice.
- **Pivot to the real Bug 2.** If repeat-enroll is merely idempotent, the lever isn't *deriving* a
  key — it's making the server generate a **genuinely new** record. Declining the pending/issued
  enrollment and re-enrolling does exactly that: a fresh UUID, a fresh keypair, and (confirmed on
  the real account) the certificate **serial is a global incrementing counter**, so the new leaf
  gets a new serial and is signed over new TBS bytes:
  ```
  leaf.crt   subject=CN=shadowklesh@gmail.com  issuer=CN=BeeCA, O=BeeCA  serial=0x1000
  leaf2.crt  subject=CN=shadowklesh@gmail.com  issuer=CN=BeeCA, O=BeeCA  serial=0x1001
  ```
  Same CN, **different serial → different TBS → different signature**. Two signatures over two
  *known* messages from a single account is precisely the input the crypto step needs — and
  combined with Thread E's unauthenticated self-approve, collecting the pair takes seconds instead
  of two human-review cycles.

### Thread G — Bug 3: recovering N, and the "aha" about `e=65537`

- **Observation.** We now hold two BeeCA-signed leaves with known TBS bytes and known signatures.
  An RSA signature is `s = EM^d mod N`, where `EM = EMSA-PKCS1v1.5(SHA256(TBS))` is something we can
  recompute byte-for-byte ourselves.
- **The blocking assumption we started from.** The standard intuition is *"`e=65537` makes
  signature-based `N`-recovery infeasible"* — with a small `e` (e.g. `e=3`) there are classic
  low-exponent attacks, but `e=65537` is supposed to close that door. Under that assumption, this
  thread looked dead before it started.
- **Why that assumption is false here.** `s^e ≡ EM (mod N)` always implies `s^e − EM = k·N` for some
  integer `k`, **regardless of the size of `e`** — the only cost is computing `s^e`, which is "just"
  a ~16 MB integer. A modern bignum library (`gmpy2`) computes it in well under a second. With two
  leaves, `N = gcd(s1^e − EM1, s2^e − EM2)` (up to a tiny cofactor stripped afterward).
- **Test.** `recover_ca_and_forge.py` implements exactly this against `leaf.crt`/`leaf2.crt`.
  ```bash
  python3 recover_ca_and_forge.py leaf.crt leaf2.crt
  # [+] recovered CA modulus N: 2048 bits (emlen guess 256)
  ```
- **Confirmed.** `s^e mod N == EM` holds for **both** leaves — the recovered 2048-bit `N` is
  genuine, not a coincidental small cofactor. The flag's own text (*WeaK_CrYpto*) suggests the
  author built this on the same "large `e` protects you" misconception.

### Thread H — factoring the recovered CA key

- **Observation.** A 2048-bit `N` recovered from a *hand-rolled* CA is a strong hint the primes
  aren't independently random — "vibecoded" crypto tends to fail on prime generation, not on the
  RSA math itself.
- **Hypothesis → test → result, run as a battery, each step a real dead end before the next:**
  - Small factors (2…47): none divide `N`.
  - Plain **Fermat** (assumes `p ≈ q`, i.e. `p/q ≈ 1`): no square found in a reasonable search
    window — the primes are not *that* close.
  - **Batch-GCD** against the leaf moduli (shared-prime reuse between CA and leaf keys): `gcd(N,
    leaf_modulus)` trivial for both leaves — no shared factor.
  - **ROCA / factordb lookup**: negative (this had already been established earlier, in Thread C/D,
    for the *leaf* keys — re-checked here for the CA modulus specifically, also negative).
- **The step further.** Fermat is the special case `k=1` of **Lehman's method**, which searches for
  primes related by a small ratio `p/q ≈ b/a` (not just `p ≈ q`) by scaling `N` by a multiplier `k`
  before the square search. Sweeping small `k`, **`k=99` factors `N` instantly** — a classic
  hand-rolled-key signature (a "quick `getPrime()`-twice" implementation whose two primes end up in
  an unbalanced-but-related ratio, not independently random).
- **Confirmed.** `p·q == N`; from there `d = e⁻¹ mod (p−1)(q−1)` reconstructs the full CA private
  key, which correctly re-signs and validates against our own known leaves.

By this point every earlier "recon fact" from §2 had turned from a blocker into a load-bearing piece
of the chain: no CN control (Thread A) → no self-sign (Thread B) → no direct CA download (Thread C)
→ but an unauthenticated internal issuer (Thread E) plus a decline/re-enroll logic gap (Thread F)
gave two signatures, and those two signatures alone were enough to break the CA (Threads G–H).

## 4. The vulnerability

Three independent bugs chain together; none alone gives `CN=admin`:

1. **Web/Logic — unauthenticated internal issuer.** `POST /internal/cert?uuid=&action=approve` on
   `certissue-bv5kavo6.internal` performs no authentication and no authorization check; its only
   protection is that the hostname is absent from public DNS. It is colocated on the same edge IP as
   the public vhosts, so any client that sets **both** TLS SNI and HTTP `Host` to that name reaches
   it directly and can self-approve (or decline) *any* existing enrollment UUID.
2. **Logic — re-enrollment is not rate-/count-limited per account.** Declining an enrollment and
   calling `/api/enroll` again generates a genuinely new record: new random RSA keypair, new random
   UUID, and a new certificate **serial** drawn from a global incrementing counter. Nothing ties the
   number of *distinct signed leaves* a single verified identity can obtain to one — so one Google
   account can produce an arbitrary number of independently-signed messages under attacker control
   (their own, fixed `CN`, but attacker-chosen serial/timing).
3. **Crypto — the CA's RSA key is both recoverable and weak.** (a) Because the padded message
   `EM = EMSA-PKCS1v1.5(SHA256(TBS))` for any leaf is fully computable from public data, two signed
   messages leak the CA modulus via `N = gcd(s1^e − EM1, s2^e − EM2)` — this holds at any public
   exponent, including `e=65537`, because `s^e` is cheap for a bignum library. (b) The CA's own key
   generation produces primes related by a small ratio (`p/q ≈ b/a`) rather than independently
   random 1024-bit primes, so Lehman's method factors the recovered `N` almost instantly once found.

Bug 1 supplies *fast* issuance, Bug 2 supplies a *second signature*, and Bug 3 turns two signatures
into the CA's private key — which is then used to sign a certificate for whatever `CN` we choose.

## 5. Exploit — step by step

1. Log in with Google, then enroll to get a real, per-account leaf (`CN` = your verified email):
   ```bash
   POST /api/enroll   # -> {"uuid": "<UUID1>", "cn": "you@example.com", "status": "pending", ...}
   ```
2. **Bug 1** — self-approve instantly via the unauthenticated internal issuer (no waiting for a
   human reviewer):
   ```bash
   curl -sk -X POST --resolve certissue-bv5kavo6.internal:443:93.77.163.176 \
     "https://certissue-bv5kavo6.internal/internal/cert?uuid=<UUID1>&action=approve"
   # -> {"ok":true,"status":"issued","uuid":"<UUID1>"}
   curl -H "Cookie: beeca_session=<SESS>" https://portal-bv5kavo6.beeca.avitoctf.ru/api/cert \
     -o beeca-client.p12
   openssl pkcs12 -in beeca-client.p12 -passin pass:beeca -nodes -clcerts \
     | openssl x509 -out leaf.crt
   ```
3. **Bug 2** — decline that enrollment and re-enroll to mint a genuinely new record (new keypair,
   new serial → new signature), then self-approve it the same way:
   ```bash
   curl -sk -X POST --resolve certissue-bv5kavo6.internal:443:93.77.163.176 \
     "https://certissue-bv5kavo6.internal/internal/cert?uuid=<UUID1>&action=decline"
   POST /api/enroll   # -> {"uuid": "<UUID2>", "cn": "you@example.com", "status": "pending", ...}
   curl -sk -X POST --resolve certissue-bv5kavo6.internal:443:93.77.163.176 \
     "https://certissue-bv5kavo6.internal/internal/cert?uuid=<UUID2>&action=approve"
   curl -H "Cookie: beeca_session=<SESS>" https://portal-bv5kavo6.beeca.avitoctf.ru/api/cert \
     -o leaf2.p12
   openssl pkcs12 -in leaf2.p12 -passin pass:beeca -nodes -clcerts | openssl x509 -out leaf2.crt
   ```
   Now `leaf.crt` (serial `0x1000`) and `leaf2.crt` (serial `0x1001`) are two distinct, genuinely
   BeeCA-signed certificates from one account.
4. **Bug 3a** — recover the CA modulus algebraically from the two signatures:
   ```bash
   python3 recover_ca_and_forge.py leaf.crt leaf2.crt
   # [+] recovered CA modulus N: 2048 bits (emlen guess 256)
   ```
5. **Bug 3b** — the tool's factoring battery runs small-factors → Fermat → batch-GCD → Lehman
   (`k=99` wins), reconstructs `d = e⁻¹ mod (p−1)(q−1)`, and builds the CA private key from
   `(N, p, q, d)`.
6. Forge a `CN=admin` leaf signed by the recovered CA key (same script): issuer
   `CN=BeeCA, O=BeeCA`, `BasicConstraints: CA=FALSE`, `KeyUsage: digitalSignature`,
   `EKU: clientAuth`, serial `0x2000` — written to `admin.crt`/`admin.key`.
7. Present it over mTLS to the admin host:
   ```bash
   curl --cert admin.crt --key admin.key https://admin-bv5kavo6.beeca.avitoctf.ru/
   ```
   The chain validates (it's genuinely CA-signed) and the app's exact `CN == "admin"` check passes.
   The admin host returns the **Первопромпт** — a satirical "vibecoder bee" manifesto
   (`firstprompt.txt`) that ends with:
   ```
   - Дают - бери. Не дают - отбери avito{uZUzUlEy_WeaK_CrYp7O_vIBeee}
   ```

All of steps 4–6 are reproduced end-to-end by `recover_ca_and_forge.py` (see §8) — it takes the two
leaf certs as its only input and writes the forged `admin.crt`/`admin.key` pair.

## 6. Flag

```
avito{uZUzUlEy_WeaK_CrYp7O_vIBeee}
```

## 7. Takeaways

1. **Network-position "security" is not security.** An internal issuer separated only by an
   unresolvable hostname is one matching `SNI`/`Host` away on a shared edge IP.
2. **Signature-based CA-modulus recovery is practical even at `e=65537`.** `s^e − EM = k·N`, then
   GCD over two certs. A large public exponent does not by itself protect the modulus once two
   known-message signatures exist — `s^e` is cheap for a bignum library.
3. **Hand-rolled CA keys are weak — run the *whole* factoring battery.** ROCA / Fermat / batch-GCD /
   **Lehman**, not just Fermat. Here only Lehman (`k=99`) cracked it; a "close primes" check alone
   would have missed it.
4. **Idempotent APIs and "deterministic-looking" behavior are not the same thing.** The single
   biggest time sink in this challenge (~230K candidate key derivations) came from mistaking an
   ordinary idempotent `POST /api/enroll` for a seeded keygen formula. Before chasing a
   crypto-derivation hypothesis, rule out the boring explanation (the server is just returning a
   stored record) — a decline/re-enroll test would have settled it in one request.
5. **A tiny logic flaw feeds the crypto.** Unlimited re-enrollment + a global incrementing serial
   produced two distinct leaves from one account — exactly the two signatures the whole attack is
   built on. The three category tags (Web + Logic + Crypto) are literally the three links of the
   chain.

## 8. Artifacts

- `recover_ca_and_forge.py` — curated end-to-end script: recovers the CA modulus `N` from ≥2 leaf
  certs (`N = gcd(s1^e − EM1, s2^e − EM2)`), factors it (small factors → Fermat → batch-GCD →
  Lehman), rebuilds the CA private key, and forges/signs a `CN=admin` certificate. Verified against
  the real `leaf.crt`/`leaf2.crt` in this folder — the recovered CA key correctly verifies the
  actual `admin.crt` that was used to fetch the flag. `ruff format` / `ruff check` clean; `ty check`
  clean (its two non-stdlib imports, `cryptography` and `gmpy2`, carry targeted
  `ty: ignore[unresolved-import]` comments, documented in the module docstring — neither package is
  a project dependency and neither ships inline type stubs).
- `RECON.md`, `WEBLOGIC_NOTES.md`, `CRYPTO_NOTES.md`, `APPROVAL_CRYPTO_NOTES.md`,
  `DETERMINISTIC_NOTES.md`, `DETKEY_CRACK_NOTES.md`, `FRESHEYES_NOTES.md`, `NOLOGIN_NOTES.md`,
  `BUNDLE_ANALYSIS.md` — the full reasoning trail (recon passes, the refuted deterministic-keygen
  crack attempt with its 230K-candidate search, the confirmed internal-issuer bug, the crypto
  recovery/factoring notes).
- `leaf.crt`/`leaf2.crt` (the two signing inputs), `admin.crt`/`admin.key` (the forged cert),
  `firstprompt.txt` (the recovered First Prompt), `artifacts/` (raw `s_client`/`p12` dumps),
  `FLAG.txt`.
