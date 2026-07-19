# BeeCA — two confirmed bugs + the deterministic-key crack plan

> ⚠️ **CORRECTION (later, well-evidenced): "Bug 2 — deterministic keygen" is REFUTED.**
> A crypto agent ran ~230K candidate derivations f(CN)→(p,q) (every random.seed/getPrime/hash/
> DRBG/PBKDF2/HKDF pattern) with ZERO hits and no near-miss signal above the ~13-bit noise floor.
> The "two enrolls → byte-identical key" observation is simply the **API returning the stored
> enrollment record idempotently per account** — NOT recomputing from a formula. Our leaf's p,q
> look like healthy os.urandom; the uuid is a genuine random v4. ⇒ the admin's key CANNOT be
> derived from CN, and the CA key CANNOT be regenerated from a seed. The ONLY crypto path is
> **GCD of two distinct leaves → N → weak-CA-key factor → forge CN=admin** (needs a SECOND
> BeeCA-signed cert we don't have). Everything below about a key-derivation crack is void; keep
> only Bug 1 (internal issuer unauth) and the GCD approach.

## Bug 1 — internal issuer reachable with ZERO auth (Web/Logic)
`certissue-bv5kavo6.internal` is a real `server{}` block colocated on the shared edge IP
`93.77.163.176`, "protected" only by the name not resolving publicly. Reach it with SNI+Host:
```
curl -sk -X POST --resolve certissue-bv5kavo6.internal:443:93.77.163.176 \
  "https://certissue-bv5kavo6.internal/internal/cert?uuid=<UUID>&action=approve"
```
No auth, no client cert needed. Only `action=approve|decline`, requires an EXISTING `uuid`,
ignores `cn=` and all extra params. Used it to self-approve our pending enrollment.

## Bug 2 — DETERMINISTIC key generation (Crypto)  ← the crypto crack
`POST /api/enroll` returns `private_key_pem`. Two enrolls (same session) → **byte-identical
private key**. So the RSA keypair is a deterministic function of the identity (CN = the Google
email, verbatim). ⇒ **the admin's private key is f("admin")** — if we recover f.

We hold a known (input → output) oracle pair:
- CN / email : `shadowklesh@gmail.com`
- enrollment uuid : `05e4cb4f-c01f-41f5-ab31-35179065ef52` (also deterministic, same across enrolls; NOT a plain md5/sha1/sha256/uuid3/uuid5 of the email)
- serial : 4096 (0x1000, fixed)
- private key : `beeca/leaf.key` (also `ourkey.pem`), n=2048-bit, p,q=1024-bit, |p-q|~1023 bits (NOT Fermat-weak)
  - p = 0xf45b290e6507a199bb6f1e1e6b84e518...
  - q = 0xae8a41e5b5e0e124aa73f0f1283a5a7e...

## The offline crack (known-plaintext on the derivation)
Find f such that f("shadowklesh@gmail.com") reproduces our EXACT p,q. Try vibecoder patterns:
- Python `random.seed(cn)` (or `random.seed(int(hashlib.sha256(cn).hexdigest(),16))`, or seed
  with md5/sha1 int, or the raw bytes) → then prime gen via `random.getrandbits(1024)` +
  nextprime (sympy) / Miller-Rabin. Match p (and q = second prime drawn).
- `Crypto.Util.number.getPrime(1024, randfunc=seeded)` (pycryptodome) with a `random`-seeded
  or hashlib-CTR randfunc.
- `random.Random(cn)` instance; numpy seed; `hashlib` stream (sha256(cn+counter)) as the byte
  source for prime candidates.
- Seed variants: cn, email, cn.lower(), cn.encode(), "BeeCA"+cn, cn+salt, the sha256/md5 hex or
  int, first 8/16 bytes, etc. Also try seeding then drawing p THEN q vs q THEN p.
Once a pattern reproduces our (p,q) from our CN → apply the SAME f to CN="admin" → **admin's
private key**.

## Then: obtain a CN=admin cert to pair with the derived key
The admin (IT-lead) already holds an ISSUED CN=admin cert (signed by BeeCA). We can't set CN at
enroll (server-derived from email) and can't forge the session JWT (HS256 strong secret,
alg:none + jwk-injection + weak-secrets all rejected). Options to get the CN=admin PUBLIC cert:
- If the enrollment **uuid is also deterministic** from CN, crack f_uuid on our known pair, then
  admin's uuid = f_uuid("admin"); look for ANY cert-download-by-uuid (certs are public — try the
  portal and the internal issuer with our client cert / unauth, /api/cert?uuid=, internal paths).
- Create a CN=admin pending enrollment by any means, then approve via Bug 1.
- Reconstruct the admin cert: its TBS is deterministic (subject CN=admin, pubkey = f_pub("admin"),
  fixed serial/validity template) — only BeeCA's signature is missing; so DOWNLOADING it is required.
The admin host is a bare mTLS gate: valid BeeCA cert + EXACT `CN==admin` on `/` → serves the
"Первопромпт". `curl --cert admin.crt --key admin.key https://admin-bv5kavo6.beeca.avitoctf.ru/`.

## Closed (don't retry)
JWT forge (alg:none/jwk/weak-secret) — rejected. Enroll CN override (body/query/header) — ignored.
sub-CA (leaf CA:FALSE, no keyCertSign) — dead. BeeCA CA cert — not served anywhere found.
Feedback moderator — log-only sink, no bot. OAuth cancel/error — fail-closed.
