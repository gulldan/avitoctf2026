# СОТЭК — write-up

**Flag:** `avito{vERy_Sus_b4DGeR_Detect3d_bY_cAMerA}`
**Class:** Web — second-order (stored) SQL injection → blind boolean session-token exfil → session replay.

---

## 1. The challenge

СОТЭК is a delivery service. A parcel (a "disguise kit") was **mis-delivered**; the only
delivery-proof photo lives in the receiving **agent's cabinet**, and her password is
inaccessible. Task: find out **who actually received the parcel** — i.e. get into that agent's
cabinet and read the proof. Provided: the app **source** (Next.js / TypeScript, `better-sqlite3`).

## 2. Where the flag lives (and why the obvious paths are dead)

Grepping the source, `getIssuedOrdersForUser(userId)` stamps **`process.env.FLAG`** onto the
response whenever the user has a **non-empty** order list. Only **one** seeded user has an order:

- agent **`agent.bzz@hive.local`**, order `SOT-2026-0001`, with the proof photo.
- Her password is a server-side **`crypto.randomUUID()`** — not in the source, not brute-forceable.

So we can't log in as her by password and we can't register *ourselves* into her order. The only
way to reach `getIssuedOrdersForUser` **as her** is to ride her **session**.

## 3. The bug — second-order SQLi through `postal_code`

Two source facts combine:

**(a) `register/route.ts` never validates `postalCode`** before inserting it — it takes the raw
form string and hands it straight to `createUser`:

```ts
const postalCode = String(formData.get("postalCode") ?? "");  // no cast, no validation
const userId = createUser({ email, password, fullName, postalCode });
```

`createUser` inserts this into the `postal_code INTEGER` column. Here's the subtlety that makes it
exploitable: SQLite uses **dynamic typing / type affinity**, so a *non-numeric* string is stored
**verbatim as TEXT** despite the declared `INTEGER` affinity. The attacker therefore fully controls
the exact bytes that come back as `user.postal_code` on every later request.

**(b) `rates.ts::calculateRatesForUser` string-interpolates it, unescaped**, into a query
(`src/lib/rates.ts`):

```ts
const zipcode2ratesQuery = `
  SELECT DISTINCT rate_id FROM zipcode2rates
  WHERE postal_code IN ('${profilePostalCode}', '${destinationPostalCode}', '125315', '190000')
`;
const rateRows = db.prepare(zipcode2ratesQuery).all();
```

reached at runtime from **`POST /api/calculate`**. (`destinationPostalCode` is `Number()`-coerced in
the route handler, so that side is safe; `profilePostalCode` is the poisoned stored value.) Because
the tainted value is *stored* at register-time and *executed* later at calculate-time, this is a
**second-order** injection — the sink never sees user input directly, which is exactly why it's easy
to miss when you only audit "where does input reach a query".

## 4. Turning it into a boolean oracle

`better-sqlite3`'s `.prepare()` **rejects stacked statements**, so no `; UPDATE …`. But the query
returns a **`rates` array**, and whether it's populated is attacker-observable — a classic **blind
boolean** oracle. Register accounts whose `postalCode` is a crafted `UNION`:
```
x') UNION SELECT CASE WHEN (<condition>) THEN 101 ELSE NULL END --
```
- condition true → a `101` rate appears in `/api/calculate`'s response,
- condition false → empty.

With that oracle, **binary-search each character** of the target: the live **session token** for
`agent.bzz@hive.local` out of the `sessions` table (join `sessions`→`users` on the agent's email).
Drive all **36 UUID positions in parallel**, ~5 requests each (register → calculate per guess).
Recovered token:
```
090d8f5e-9a49-4d7f-a1ee-9f9ca715f348
```

## 5. Session replay → the flag

Replay the stolen session straight at the cabinet:
```
curl -b "session_id=090d8f5e-9a49-4d7f-a1ee-9f9ca715f348" https://sotek-<id>.avitoctf.ru/orders
```
The server resolves the session to the agent, `getIssuedOrdersForUser` finds her one order,
stamps `process.env.FLAG`, and renders it **overlaid on the delivery-proof photo** — the badger
caught on camera.

## 6. Flag

```
avito{vERy_Sus_b4DGeR_Detect3d_bY_cAMerA}
```

## 7. A decoy worth naming

Some error strings in the source carry **hidden-Unicode steganography** (variation selectors)
that decodes to a *different* fake-flag URL (a `zaletay-…` link). It's a **rabbit hole** — it goes
to a meme, not the flag. We logged it in `MEMES.md` and did **not** follow it as a solution path.
The real signal was always the `FLAG`-stamping code path gated on owning an order.

## 8. Takeaways

1. **Second-order SQLi**: an unvalidated field that looks inert at the insert (into a nominally
   `INTEGER` column) becomes live when a *later* code path interpolates it into SQL. Audit where
   stored values are *read*, not just where inputs land.
2. Stacked-statement protection (`better-sqlite3`) blocks writes but **not** a `UNION`-based
   read; any attacker-observable branch (here, a populated `rates` array) is a boolean oracle
   good enough to exfiltrate secrets character by character.
3. When a target's password is unrecoverable by design (`randomUUID()`), **steal the session**,
   not the password.

**Artifacts:** `NOTES.md` (full chain, oracle payloads, recovered token), `FLAG.txt`.
