# BeeCA — deterministic-keygen crack attempt: NEGATIVE RESULT (with reasoning)

## TL;DR

I could **not** reproduce our real leaf key's `(p, q)` from `CN="shadowklesh@gmail.com"` despite an
exhaustive search (~230,000+ candidate derivations across every plausible "vibecoded" and
"professional" Python pattern). A decoupled near-miss ranking found **zero signal above the noise
floor** — not "close but not quite," genuinely nothing. Combined with contradicting statements
already in the team's own notes (see below), I now assess the **"RSA keypair is a deterministic
pure function of CN" premise as likely FALSE**. The much simpler, already-independently-verified
explanation for "two enrolls → identical key" is that `POST /api/enroll` is **idempotent** — it
returns the same persisted DB record on repeat calls — not that it recomputes a keypair from a
seed formula. Sent this as an interim flag to the coordinator before finishing (see thread); this
file is the full writeup.

**Tasks 2–4 (derive admin.key, obtain a CN=admin cert, win) were not attempted** — they all depend
on Task 1 (crack f_key) succeeding, which it did not.

## What was tried (Task 1)

Backend confirmed **Python/Flask (Werkzeug)** via error-page fingerprinting (see
`WEBLOGIC_NOTES.md` §backend), so the search focused entirely on Python-side derivation patterns.

Oracle pair used throughout:
- CN: `shadowklesh@gmail.com`
- `p = 0xf45b290e...f7611c5c...004de96e7b` (1024-bit, from `beeca/leaf.key`)
- `q = 0xae8a41e5...dee822b7f` (1024-bit)
- enrollment uuid: `05e4cb4f-c01f-41f5-ab31-35179065ef52` (RFC4122 v4/variant-10xx shaped)

### Sweep 1 — paired sequential draws (`crack.py`)
`Crypto.Util.number.getPrime(1024, randfunc=...)` called for real (not reimplemented) with a
`random.Random(seed)`-backed randfunc (byte-by-byte `getrandbits(8)` and `randbytes(n)` styles) and
with hashlib-CTR (`sha256`/`md5`) randfuncs — drawing p then q from one continuing stream, checked
against 46 seed variants (raw/lower/upper/local-part email, `"BeeCA"+cn`, `cn+"BeeCA"`, salt/key/
keygen prefixes, md5/sha1/sha256/sha512 as hex/int/bytes/truncations, uuid3/uuid5 of cn under 4
namespaces as extra seed material). Also `random.getrandbits(1024)` + `sympy.nextprime` search
(inclusive & exclusive, with/without forcing top-bit+odd), and a "redraw-until-prime" style
(`sympy.isprime` loop, mimicking `getPrime`'s re-randomize-on-failure behavior but via direct
`getrandbits`). ~5 min runtime, **zero matches**.

### Sweep 2 — decoupled single-target search (`crack2.py`)
Realized pairing (which seed → which draw is "p" vs "q", possibly with an offset draw in between
for e.g. the uuid) massively multiplies the guess space. Instead: generate a candidate 1024-bit
integer via many (seed-material × expansion-method) combos, then check `nextprime` (inclusive/
exclusive, forced/unforced) against **both** P and Q independently — a hit doesn't require guessing
the pairing, just one formula that lands on one of the two targets. 134 seed materials (broadened
with `:p`/`:q`/`-p`/`-q` suffixes, HMAC-BeeCA/beeca variants, 10 hash algorithms including sha3/
blake2) × expansion via `random.Random.getrandbits(1024)`, `.randbytes(128)`, hashlib-CTR (sha256/
md5/sha1), hashlib hash-chain (no counter), SHAKE128/256, PBKDF2 (multiple salts/iteration counts)
→ **18,441 candidates checked, zero matches**.

### UUID-focused sweeps (`crack_uuid.py`, `crack_uuid2.py`, `crack_uuid3.py`)
The uuid is a *much* cheaper oracle (RFC4122 forces version=4/variant bits via
`uuid.UUID(int=x, version=4)`-style masking, confirmed by inspecting `uuid.UUID.__init__` source —
so checking is a direct 128-bit equality test after masking, no primality search needed). Broadened
to 938 seed materials × RNG draw styles (`getrandbits(128)`, `randbytes(16)`, byte-by-byte) × 0–5
"prior draw" offsets (in case something else — like the uuid itself, or vice-versa — is drawn first
from a shared stream) + direct-digest-truncation checks (`md5(cn)` is conveniently exactly 16 bytes)
→ **76,325 candidates, zero matches**. Then tried "professional CSPRNG" constructions — HKDF (with
various salts and `context=` labels `b"uuid"`/`b"p"`/`b"q"`), AES-CTR-DRBG keystream, ChaCha20
keystream, each keyed by sha256/md5/sha512 of cn with various prefix salts → **105 candidates, zero
matches**.

### Near-miss ranking (`crack_nearmiss.py`) — the key diagnostic
Rather than requiring exact equality, ranked ~10,000 candidates (same seed-material × expansion
combos as above) by **shared-prefix bit-length** against REAL_P and REAL_Q. A formula that's
*correct in spirit* but off on some detail (wrong endianness, off-by-one draw offset, forcing
convention) would show up as an anomalously long shared prefix even without an exact hit. Result:
**best hit was 13 shared bits** — exactly the expected order statistic for pure chance
(`log2(10000) ≈ 13.3`). No candidate family showed any signal above noise. This is the strongest
evidence: it's not "haven't found the right seed yet," there's no partial correctness anywhere in a
very broad net.

### Final targeted checks (`crack_final.py`)
`PYTHONHASHSEED=0; hash(cn)` as a seed (in case a vibecoder used Python's builtin `hash()` thinking
it's deterministic) — no match. Real `sympy.randprime()` invocation (not reimplemented — it
internally uses `random.randint`, which consumes the seeded MT stream slightly differently than
`getrandbits(1024)` directly) — no match. `numpy` not installed in the venv (not tried; low priority
since backend is Flask/Python but nothing suggests numpy specifically).

**Total: ~230,000+ candidate derivations tried across the paired, decoupled, near-miss-ranked, and
CSPRNG-flavored sweeps. Zero exact matches, zero near-miss signal.**

## Why I now doubt the premise itself

1. **`APPROVAL_CRYPTO_NOTES.md`** (a later, careful pass, §2.2 "Partial, indirect signal") already
   states: *"extracted p/q from our own issued leaf's private key ... both are proper ~1024-bit
   primes with |p−q| also ~1023 bits (no Fermat-close-primes weakness, no small factors, **looks
   like healthy os.urandom-backed generation**)"* and separately (§Frontier 1) that the enrollment
   uuid is *"a genuine random UUIDv4 (122 bits entropy), unenumerable"* — **directly contradicting**
   `DETERMINISTIC_NOTES.md`'s claim that the uuid is deterministic.
2. **`FRESHEYES_NOTES.md`** (most recent, session-live pass) states plainly: *"/api/enroll is
   idempotent and returns private_key_pem"* and separately confirms *"decline+re-enroll returns the
   same record"* (§ranked theory #1 step 1 note, and the "Blocker for #1" line). This is the much
   simpler, standard explanation for "two enrolls give the same key": the server persists one
   enrollment record per Google account and returns it as-is on every subsequent call — completely
   ordinary idempotent API design, not evidence of a seeded-PRNG keygen formula.
3. My own quick statistical check on p/q (bit-balance 480/1024 and 525/1024 ones — both within 2
   standard deviations of the expected 512 for a fair-coin sequence of that length; longest
   identical-bit run 14 and 9, consistent with random 1024-bit strings; byte-repeat distribution
   normal) shows nothing anomalous — consistent with (but doesn't distinguish between) real
   `os.urandom` and a well-built seeded CSPRNG.

None of this is airtight proof there's no `f(CN)` — a sufficiently obscure or salted construction
could still exist and simply wasn't in my search space (e.g. if there's a server-side secret pepper
mixed into the seed, cracking is fundamentally impossible from `CN` alone no matter how exhaustive
the guess list). But given (a) the total absence of exact matches AND near-miss signal across an
extremely broad, methodically-designed search, and (b) two independent, more-rigorous later passes
on this same target both concluding "looks like real randomness" / "it's just idempotent," I think
continued brute-forcing of guessed formulas is a poor use of further effort.

## Recommendation

Pivot fully to `FRESHEYES_NOTES.md`'s evidence-backed plan: get a second Google account/leaf and
run the already-built `beeca/recover_ca_and_forge.py` GCD-of-two-signatures attack
(`N = gcd(s1^e − EM1, s2^e − EM2)`) to recover the CA's modulus, then run its weak-key battery
(Fermat/close-primes etc.) to recover the CA private key and forge a `CN=admin` leaf. That plan is
backed by a demonstrated, working proof-of-concept (self-tested end-to-end per that note), unlike
the deterministic-keygen angle which is backed only by one ambiguous behavioral observation that has
a simpler explanation.

## Scripts (kept in scratchpad, not the repo)
`/private/tmp/claude-502/-Users-mmk-github-avitoctf2026/48acb495-4b63-4434-8bd8-2718f79a45a2/scratchpad/`:
`crack.py`, `crack2.py`, `crack_uuid.py`, `crack_uuid2.py`, `crack_uuid3.py`, `crack_nearmiss.py`,
`crack_final.py`. Reusable if new oracle pairs or seed hypotheses turn up (e.g. a second leaf, or a
confirmed algorithm hint) — each accepts a `REAL_P`/`REAL_Q` constant swap.
