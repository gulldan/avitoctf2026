# BeeCA — FRESH-EYES re-analysis (challenging the team's assumptions)

Analyst pass with the **real issued leaf cert now in hand** (`leaf.crt`/`leaf.key`, cn=shadowklesh@gmail.com)
and a **live session cookie**. All prior notes (`RECON`, `BUNDLE_ANALYSIS`, `WEBLOGIC_NOTES`,
`CRYPTO_NOTES`, `NOLOGIN_NOTES`) were written *before* a cert existed and are largely obsolete on the
crypto/logic questions. Everything below was re-verified live this pass.

## TL;DR — top theory + single best next action

- **The team's #1 hypothesis (sub-CA / BasicConstraints abuse) is DEAD**: the issued leaf is
  `BasicConstraints: CA:FALSE (critical)` + `KeyUsage: Digital Signature only`. A CA:FALSE leaf cannot
  sign a valid chain. Stop pursuing it.
- **Intended path (ranked #1): CRYPTO — recover the CA modulus N from ≥2 issued leaves, factor a weak
  CA key, forge a `CN=admin` cert.** The task's stated assumption *"e=65537 ⇒ signature-only N-recovery
  is infeasible"* is **WRONG and I proved it**: `N = gcd(s1^e − EM1, s2^e − EM2)` runs in **~22 s** with
  gmpy2 (self-test recovered a 2048-bit N exactly and Fermat-factored a close-prime CA instantly). Tool:
  `beeca/recover_ca_and_forge.py`.
- **Blocker for #1:** enrollment is **pinned one-cert-per-Google-account** (verified: decline+re-enroll
  returns the same record). So you need a **second distinct leaf = a second Google account.**
- **SINGLE HIGHEST-VALUE NEXT ACTION:** enroll **one more throwaway Google account** — ideally emailed
  `admin<random>@gmail.com` — and download its `.p12`. Self-approve it **instantly** via the Host bug
  (below), no 7-min wait. That single second leaf simultaneously:
  (a) lets you **test theory #2** (loose CN check) by presenting it to the admin host, and
  (b) gives you leaf₂ so `recover_ca_and_forge.py leaf.crt leaf2.crt` recovers N → factors → forges
  `CN=admin`.

---

## CONFIRMED NEW BUG (definitely intended — the "Logic" piece)

**`Host: certissue-bv5kavo6.internal` on the shared public edge reaches the internal issuer, and
`/internal/cert` approve/decline works with NO authentication (no client cert, no session; GET *or*
POST — so it's even CSRF-able).**

```
# instant, unauthenticated approve of ANY existing enrollment:
curl -H 'Host: certissue-bv5kavo6.internal' -X POST \
  'https://portal-bv5kavo6.beeca.avitoctf.ru/internal/cert?uuid=<UUID>&action=approve'
# -> {"ok":true,"status":"issued","uuid":"<UUID>"}
```

- Gate is the **Host header only** (tested: works *without* the client cert too). The prior notes'
  "Host-spoof dead-ends in default_server" conclusion was wrong — they tested via `--resolve`/SNI, not a
  Host header over a valid portal TLS connection. `certissue-bv5kavo6.internal` is a real configured
  vhost on the edge (other internal names like `admin-*.internal`, `hive-*.internal` reset the conn).
- Constraints: only `action=approve|decline`; **only EXISTING uuids** (random uuid → `not found`);
  `cn`/`email`/`subject` override params are **ignored**. So this alone does **not** set CN=admin — it
  removes the moderated ~7-min auto-approver from the loop, letting you self-issue any enrollment you can
  create.

---

## RANKED THEORY OF THE INTENDED SOLUTION

### #1 — Crypto: forge a BeeCA-signed `CN=admin` cert  (best fit for the "Crypto" tag)
1. Enroll account A → leaf₁ (have it). Enroll account B → leaf₂ (needs 2nd Google account).
2. `N = gcd(s1^e − EM1, s2^e − EM2)` where `EM_i = EMSA-PKCS1v1.5(SHA256(TBS_i))` is fully known.
   **Proven feasible with e=65537** (~22 s). This is the "aha" the author likely thinks e=65537 prevents.
3. Weak-key battery on N (Fermat/close-primes is the overwhelming favorite for a hand-rolled "vibecoder"
   CA; also small-factor and batch-GCD-with-leaf-moduli — all wired up in the tool).
4. Rebuild CA private key → sign a `CN=admin` leaf (`CA:FALSE`, EKU=clientAuth, issuer exactly
   `CN=BeeCA, O=BeeCA`) → present to admin mTLS → read **Первопромпт**.
- Residual risk: if the CA modulus is *not* weak, this dies at step 3. But the task's own hint #4
  ("run the full weak-key battery") strongly implies it IS weak once you have N. (Note: the *leaf* keys
  are normal RSA-2048, not Fermat/ROCA-weak — the CA key is a separate, likely-deliberately-weak key.)

### #2 — Logic: loose CN check at the admin host  (cheapest to test first)
The admin host, given our valid cert, returns:
`Сертификат подлинный и выпущен этим ульем (CN='shadowklesh@gmail.com'), но прав администратора
недостаточно: требуется CN=admin.` — it **echoes the full CN** and demands `CN=admin`.
- If the check is `startswith("admin")` / substring / `cn.split('@')[0]=="admin"`, then a throwaway
  **`admin<random>@gmail.com`** (or `admin@<your-workspace-domain>`) yields a cert that passes with **no
  crypto at all**. Test by presenting that leaf to `https://admin-bv5kavo6.beeca.avitoctf.ru/`.
- The response phrasing ("требуется CN=admin", exact word) *leans* toward an exact `== "admin"` compare
  (which only crypto-forge satisfies), so this is ranked #2 — **but it costs one throwaway account to
  falsify and would be the whole solution if it hits.** Use the SAME 2nd account as #1.

### #3 — Prompt-injection into the moderator/auto-approver ("vibecoder bees" / "Первопромпт")
Flavor implies an LLM in the approval loop. Prior feedback-channel injection showed no OOB effect, and
`/api/feedback` is a latency-flat async log sink. Low confidence, but **now testable with a session**:
the effect (a cn change / issuance) would show up in `/api/me`, not OOB — only worth a look if #1/#2
stall. (Hard to drive: our record is issued and can't be pushed back to `pending`.)

---

## WHAT I DEFINITIVELY CLOSED THIS PASS (don't re-spend time here)
- **Sub-CA / self-sign**: leaf is `CA:FALSE`+DigitalSignature-only. Dead.
- **Admin header spoofing *with a valid cert***: nginx reads the real `$ssl_client_s_dn_cn`; every
  `X-SSL-*`/`X-Client-*`/`X-Forwarded-Client-Cert` override still echoes our real CN. Closed.
- **Enroll CN override**: body `{cn,email,subject,name}`, query, `X-Forwarded-Email`, and the internal
  (certissue) vhost — **all ignored**; CN is strictly the session email, pinned per account.
- **Session JWT forgery**: HS256, strong secret (rockyou + best66 + mask ≤7 alnum + ~1k curated/themed
  guesses — no hit); alg-confusion (`none`/`None`/`NONE`/empty-key) rejected; **jwk/jku/kid header
  injection** rejected. The JWT path is genuinely hard.
- **CA cert retrieval**: not on any portal/admin/issuer path (with or without client cert), no OCSP
  staple on admin TLS, p12 and `/api/cert` are **leaf-only** (no chain param/Accept works), issuer vhost
  exposes only `/internal/cert`. ⇒ N must be *recovered from signatures*, not downloaded.
- **Leaf keys**: normal RSA-2048 (|p−q|≈1023 bits, not ROCA). Weakness, if any, is in the CA key only.

## Key live facts / repro
- Admin `/` with our cert → 403 "…(CN='shadowklesh@gmail.com')…требуется CN=admin" (keep-alive: app
  reached, real chain-validation passed). All other admin paths → app-level 404.
- Enrollment: uuid `05e4cb4f-c01f-41f5-ab31-35179065ef52`, cn `shadowklesh@gmail.com`, serial `4096`
  (0x1000 — suspiciously round, possibly constant/predictable across issuances), issued. **Left in
  `issued` state (restored after a decline/re-enroll probe).**
- Session cookie in the task prompt was live (`/api/me` authenticated, ~min-scale expiry); `/api/enroll`
  is idempotent and returns `private_key_pem`.

## Tooling
- `beeca/recover_ca_and_forge.py` — give it ≥2 leaf certs; recovers N via GCD, runs the weak-key
  battery, and (if factorable) writes `admin_forged.crt`/`admin_forged.key`. Self-tested end-to-end.

## Status: no flag yet — blocked only on obtaining a **second BeeCA leaf** (one extra Google account).
