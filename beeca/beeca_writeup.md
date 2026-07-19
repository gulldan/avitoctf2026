# BeeCA — write-up

**Flag:** `avito{uZUzUlEy_WeaK_CrYp7O_vIBeee}`
**Class:** Crypto + Web + Logic — **Hard, 0 teams solved**, 1000 pts (author @v1ru55, SPbCTF).

**One-paragraph story of the solve.** The prize (the "Первопромпт" / First Prompt) lives behind an
mTLS wall that only opens for a client certificate whose subject is exactly `CN=admin`. You can only
get certificates named after *your own* verified Google email, and the naive "self-sign a CN=admin
cert" is rejected because the wall does real chain validation. So the whole challenge is: **how do
you obtain a certificate the BeeCA certificate authority never intended to issue?** The answer is a
three-bug chain — (1) an *unauthenticated* internal issuer endpoint lets us instantly self-approve
enrollments, (2) an incrementing serial counter lets us mint **two** distinct CA-signed leaves from
a single account, and (3) two signatures are enough to algebraically **recover the CA's public
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

---

## 2. Recon — mapping the certificate system

**Portal API** (recovered from the minified bundle `portal.js` / `/static/assets/index-*.js`):

| Endpoint | What it does |
|---|---|
| `GET /api/me` | session state: `{authenticated, email, enrollment:{uuid, cn, status, serial}}` |
| `POST /api/enroll` | creates an enrollment. **`CN` = your verified SSO email, verbatim.** Keypair is generated **server-side** — the JSON response even hands back `private_key_pem`. Status starts `pending` (needs operator approval). |
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

**Dead ends (all confirmed live, so a learner doesn't waste time here):**

- Enroll **ignores** any client-supplied `cn`/`email`/`subject`/`name` (query, JSON body, or
  `X-Forwarded-Email` header) — CN is strictly the SSO email. No CN-injection at issuance.
- The issued leaf is `BasicConstraints: CA:FALSE (critical)` + `KeyUsage: Digital Signature` only,
  EKU `clientAuth`. So it **cannot** act as an intermediate → **no sub-CA / self-sign path.**
- `/api/feedback` is a latency-flat async **log sink** — no reviewing bot/LLM to prompt-inject.
- Header spoofing (`X-SSL-Client-CN: admin`, `X-Forwarded-Client-Cert`, `X-SSL-CLIENT-S-DN`, …) is
  ignored — the app reads the genuine nginx `$ssl_client_s_dn_cn`, not request headers.
- The **CA certificate is not downloadable anywhere** (swept ~40 paths / subdomains / ports on all
  three vhosts; `.p12` and `/api/cert` are leaf-only, no chain param works). This is important: it
  means we cannot just grab `N` — we will have to *recover* it.
- The "keypair is a deterministic function of CN" idea was chased hard (~230k candidate seed
  derivations) and **refuted** — the leaf keys are healthy RSA-2048 (`|p−q| ≈ 1023 bits`, not
  ROCA/Fermat-weak). The weakness, if any, is in the **CA key**, not the leaves.

Recon conclusion: we can't rename our cert, can't self-sign, can't forge the session, and can't
download the CA. The only remaining lever is the *math of the signatures themselves* — and to use
it we first need **two** signed certificates. That framing drove the rest of the solve.

---

## 3. Bug 1 (Web / Logic) — the internal issuer has no authentication

Operators approve enrollments on an **internal** host `certissue-bv5kavo6.internal`. That name does
not resolve publicly — but it turns out to be *just another nginx `server{}` block on the same edge
IP* as the portal:

```
$ dig +short admin-bv5kavo6.beeca.avitoctf.ru    # 93.77.163.176
$ dig +short portal-bv5kavo6.beeca.avitoctf.ru   # 93.77.163.176   (same IP)
```

nginx selects a vhost by **SNI**, so the trick is to make *both* the TLS SNI and the HTTP `Host`
equal the internal name. `curl --resolve` sets SNI from the request URL (a bare `-H "Host:"` over a
portal TLS connection only reaches nginx's `default_server` fallback, which was the earlier notes'
red herring):

```bash
curl -sk -X POST \
  --resolve certissue-bv5kavo6.internal:443:93.77.163.176 \
  "https://certissue-bv5kavo6.internal/internal/cert?uuid=<UUID>&action=approve"
# -> {"ok":true,"status":"issued","uuid":"<UUID>"}
```

**Why this is the intended "Logic" bug:** `/internal/cert` requires **no session and no client
cert** — its only protection is *network position* (you must know/forge the internal hostname). We
fully characterized it: `action` is a strict `approve|decline` enum; `uuid` must be an existing
enrollment (random UUIDs → `not found`); every override param (`cn`, `email`, …) is silently
ignored; no other internal route exists. So it doesn't let us *rename* a cert — but it lets us
**instantly self-approve any enrollment we create**, deleting the ~7-minute human-approval delay from
the loop. That speed is exactly what Bug 2 needs.

> Segmentation-by-obscurity is not segmentation: an "internal only" service that shares an edge IP is
> one matching `SNI`/`Host` away.

---

## 4. Bug 2 (Logic) — two distinct leaves from a single account

Enrollment *looks* like one-cert-per-account. But the certificate **serial is a global incrementing
counter**, and declining the current enrollment and re-enrolling mints a **new** record — new random
keypair, new serial, and therefore a **new signature over new TBS bytes**. Concretely, from the one
Google account we harvested two genuinely distinct BeeCA-signed leaves (verified from the artifacts):

```
leaf.crt   subject=CN=shadowklesh@gmail.com  issuer=CN=BeeCA, O=BeeCA  serial=1000
leaf2.crt  subject=CN=shadowklesh@gmail.com  issuer=CN=BeeCA, O=BeeCA  serial=1001
```

Same CN, **different serial → different to-be-signed bytes → different signature**. Two signatures
over two *known* messages is precisely the input the crypto step requires. (Combine with Bug 1: each
`pending` leaf is self-approved instantly via the unauth internal endpoint, so collecting the pair
takes seconds instead of two review cycles.)

---

## 5. Bug 3 (Crypto) — recover the CA modulus from signatures, then factor it

### 5.1 Why two signatures reveal `N`

An RSA signature is `s = EM^d mod N`, where the padded message
`EM = EMSA-PKCS1v1.5(SHA256(TBS))` is **fully known to us** — we hold each leaf, so we hold each
`TBS` (`tbs_certificate_bytes`) and can recompute its padding byte-for-byte. Raising back up with the
public exponent:

```
s^e ≡ EM   (mod N)      ⇒      s^e − EM = k·N   for some integer k
```

With **two** leaves we get two such multiples of `N`, and their GCD is `N` (up to a tiny cofactor we
strip):

```
N = gcd( s1^e − EM1 ,  s2^e − EM2 )
```

> **The "aha" that unblocks the whole challenge.** The natural assumption is *"e = 65537 makes
> signature-based `N`-recovery infeasible."* **That is false.** `s^e` is only a ~16 MB integer;
> `gmpy2` computes it in well under a second and the GCD is instant. The author appears to have
> relied on this misconception — the flag literally reads *WeaK_CrYpto*.

### 5.2 The tool

`recover_ca_and_forge.py` implements exactly this. The load-bearing pieces:

```python
E = 65537
SHA256_DI_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")

def emsa(tbs, emlen):                       # rebuild EMSA-PKCS1v1.5(SHA256(TBS))
    di = SHA256_DI_PREFIX + hashlib.sha256(tbs).digest()
    ps = b"\xff" * (emlen - len(di) - 3)
    return int.from_bytes(b"\x00\x01" + ps + b"\x00" + di, "big")

def recover_N(leaves):                      # N = gcd(s_i^e - EM_i) over the leaves
    for emlen in (256, 384, 512, 128):      # try candidate CA modulus byte-lengths
        g = 0
        for tbs, s, _ in leaves:
            g = ggcd(g, mpz(pow(mpz(s), E)) - emsa(tbs, emlen))
        g = strip_small_cofactors(int(g))
        if g.bit_length() >= 1500:
            return g                        # a real 2048-bit CA modulus
```

Run it on the pair:

```bash
python3 recover_ca_and_forge.py leaf.crt leaf2.crt
# [+] recovered CA modulus N: 2048 bits (emlen guess 256)
```

We verify the recovery is genuine by checking `s^e mod N == EM` for **both** leaves.

### 5.3 Factoring the hand-rolled CA key

The recovered `N` is a real 2048-bit modulus and shrugs off the usual battery — **ROCA, Fermat,
Pollard `p−1`, factordb lookup, and shared-prime GCD against the leaf moduli all fail.** The
`battery()` in the tool wires up small-factor + Fermat/close-prime + batch-GCD; the CA needed one
step further. **Lehman's method with multiplier `k = 99` factors it instantly**: the CA's primes
satisfy `p/q ≈ b/a` for a small fraction `a/b`, so scaling `N` by `k` before the Fermat-style
square search collapses it in one shot. (Lehman generalizes Fermat — Fermat is just `k = 1` — which
is why the plain close-prime test missed it.) A classic hand-rolled *"I wrote my own crypto"* key.

From `p, q` the CA private exponent is `d = e⁻¹ mod (p−1)(q−1)` → we reconstruct the full **CA
private key**.

---

## 6. Forge `CN=admin` → read the First Prompt

With the CA key in hand, we build a client certificate that mimics a normal BeeCA leaf but with the
one field that matters changed:

- `subject = CN=admin`
- `issuer = CN=BeeCA, O=BeeCA` (must match the trusted CA subject **exactly**)
- our own fresh RSA public key
- extensions identical to a real leaf: `BasicConstraints: CA:FALSE`, `KeyUsage: digitalSignature`,
  `ExtendedKeyUsage: clientAuth`
- **signed with the recovered CA private key**

The tool writes it out (in the repo as `admin.crt` / `admin.key`, `subject=CN=admin`,
`issuer=CN=BeeCA, O=BeeCA`, `serial=2000`). Present it over mTLS:

```bash
curl --cert admin.crt --key admin.key https://admin-bv5kavo6.beeca.avitoctf.ru/
```

The chain validates (it's genuinely signed by the CA), the app's exact `CN == "admin"` check passes,
and the admin host returns the **Первопромпт** — a satirical "vibecoder bee" manifesto
(`firstprompt.txt`) that ends with:

```
- Дают - бери. Не дают - отбери avito{uZUzUlEy_WeaK_CrYp7O_vIBeee}
```

---

## 7. Flag

```
avito{uZUzUlEy_WeaK_CrYp7O_vIBeee}
```

---

## 8. Full chain (one line each)

1. Google login → `POST /api/enroll` → `pending` leaf #1 (`CN=your-email`, serial `0x1000`).
2. **Bug 1:** self-approve instantly via the unauthenticated internal issuer
   (`--resolve certissue-…internal … action=approve`) → download leaf #1 (`.p12`, pw `beeca`).
3. **Bug 2:** decline leaf #1, re-enroll → leaf #2 (serial `0x1001`, new key/signature); self-approve
   → download leaf #2. Now we hold two distinct signatures over two known messages.
4. **Bug 3a:** `N = gcd(s1^e − EM1, s2^e − EM2)` → recover the 2048-bit CA modulus (works at
   `e=65537`; verify `s^e mod N == EM`).
5. **Bug 3b:** Lehman (`k=99`) factors `N` → `p, q` → `d` → **CA private key**.
6. Forge `CN=admin` cert (issuer `CN=BeeCA, O=BeeCA`, `CA:FALSE`, `clientAuth`) signed by the CA key.
7. `curl --cert admin.crt --key admin.key https://admin-…/` → First Prompt → flag.

---

## 9. Takeaways

1. **Network-position "security" is not security.** An internal issuer separated only by an
   unresolvable hostname is one matching `SNI`/`Host` away on a shared IP.
2. **Signature-based CA-modulus recovery is practical even at `e=65537`.** `s^e − EM = k·N`, then GCD
   over two certs. Don't assume high `e` protects you — `s^e` is a small computation for a bignum
   library.
3. **Hand-rolled CA keys are weak — run the *whole* battery.** ROCA / Fermat / **Lehman** / `p−1` /
   `p+1` / batch-GCD, not just Fermat. Here only Lehman (`k=99`) cracked it.
4. **A tiny logic flaw feeds the crypto.** An incrementing serial + decline/re-enroll produced two
   distinct leaves from one account — exactly the two signatures the whole attack is built on. The
   categories (Web + Logic + Crypto) are literally the three links of the chain.

---

**Artifacts:** `RECON.md`, `WEBLOGIC_NOTES.md`, `CRYPTO_NOTES.md`, `APPROVAL_CRYPTO_NOTES.md`,
`DETKEY_CRACK_NOTES.md`, `FRESHEYES_NOTES.md`, `recover_ca_and_forge.py`,
`leaf.crt`/`leaf2.crt` (the two signing inputs), `admin.crt`/`admin.key` (the forged cert),
`firstprompt.txt` (the recovered First Prompt), `artifacts/` (raw `s_client`/`p12` dumps), `FLAG.txt`.
