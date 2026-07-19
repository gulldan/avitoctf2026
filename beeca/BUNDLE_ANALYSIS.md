# BeeCA — `portal.js` exhaustive static analysis

Deminified map of `portal-bv5kavo6.beeca.avitoctf.ru` React/Vite bundle
(`/static/assets/index-CispjmHt.js`, 155 722 bytes, no sourcemap). Every claim below quotes the
exact minified substring it is based on. Offsets are byte offsets into `portal.js`.

Component/identifier legend (recovered):
- `Qd` = root `App`; `Dd` = enroll hero (renders `CN=`); `$d` = status card; `rc` = log box;
  `Ud` = feedback card wrapper; feedback-done view is the inner return of `Ud`;
  `Ad` = the enroll/download/log container (`onEnroll`,`onDownload`); `Vd` = **operator console**.
- `lc` host table, `uc()`/`Li()`/`Hd()` host logic, `Wd()`/`ic` role logic, `Fd` status-message map,
  `Bo="/internal/cert"`.
- React alias `M`=React, `v`=jsx-runtime. None of these are endpoints.

---

## 1. Endpoint / URL map

| # | Method | Path | Where (fn) | Body / params | Headers | creds | Response handling |
|---|--------|------|-----------|---------------|---------|-------|-------------------|
| 1 | GET | `/api/me` | `Qd` (App load) | — | — | `same-origin` | `r(await m.json())` → app state `me` |
| 2 | POST | `/api/enroll` | `Ad.i` (onEnroll) | **none** (bare POST, no CSR, no JSON) | — | `same-origin` | reads `{serial,cn,status,error}`; then `fetchMe()` |
| 3 | GET | `/api/cert` | `Ad.o` (onDownload) | — | — | `same-origin` | ok→`blob()`→download `beeca-client.p12`; !ok→`{message,error}` |
| 4 | POST | `/api/feedback` | `Ud.c` | JSON `{request_id, message}` | `Content-Type: application/json` | `same-origin` | `s(w)`; **renders `w.message` via `dangerouslySetInnerHTML`** |
| 5 | POST | `/internal/cert?uuid=<>&action=approve\|decline` | `Vd.s` (operator) | query only (`uuid`,`action`) | — | `same-origin` | reads `{status,error}` |
| 6 | GET | `/login` | `Dd` / header `<a href>` | — | — | (browser nav) | Google SSO redirect (server-side) |
| 7 | POST | `/logout` | header `<form action=... method=post>` | — | — | (browser nav) | — |

Exact substrings:

- **`/api/me`** (offset 153530):
  `const m=await fetch("/api/me",{credentials:"same-origin"});r(await m.json())`
- **`/api/enroll`** (148703): `await fetch("/api/enroll",{method:"POST",credentials:"same-origin"})`,
  then `u(`[enroll] serial=${h.serial} cn=${h.cn} status=${h.status}`)`,
  `n(h.status==="pending"?"Заявка создана. Ждите аппрува.":"Заявка уже существует.","success")`.
  **No request body, no CSR** — server does keygen and derives CN.
- **`/api/cert`** (149109): `fetch("/api/cert",{credentials:"same-origin"})` →
  `Object.assign(document.createElement("a"),{href:URL.createObjectURL(h),download:"beeca-client.p12"}).click()`
  → toast `"Импортируйте beeca-client.p12 ... Пароль: beeca"`. p12 password **`beeca`** is hardcoded UI text.
- **`/api/feedback`** (146668):
  `fetch("/api/feedback",{method:"POST",headers:{"Content-Type":"application/json"},credentials:"same-origin",body:JSON.stringify({request_id:r,message:u})})` → `s(w)`.
- **`/internal/cert`** (150312 / inside `Vd`):
  `const Bo="/internal/cert"` and
  `fetch(`${Bo}?uuid=${encodeURIComponent(m)}&action=${c}`,{method:"POST",credentials:"same-origin"})`
  where `c ∈ {"approve","decline"}`.
- **`/login`** (143354): `v.jsx("a",{className:"btn btn-secondary",href:"/login",children:"Войти через Google"})`
  and (144263) `href:"/login",children:"Начать вход"`.
- **`/logout`** (143162): `v.jsx("form",{action:"/logout",method:"post",...})`.

The only other `fetch(` in the file — `fetch(l.href,u)` at offset 689 — is the **Vite module-preload
polyfill**, not an app endpoint.

Note on same-origin: endpoints 2–5 are **relative paths with `credentials:"same-origin"`**. They resolve
against whatever origin the page is currently served from — the portal origin for a normal user, the
**internal issuer origin** for whoever is running the console on `certissue-…​.internal`. This is the crux
of the whole design (see §2, §6).

---

## 2. Host / token logic and the operator flow

### 2.1 Host table + derivation (offset 150312, `Vd` region)

```js
const lc = {
  external: { prefix:"portal-",    base:".beeca.avitoctf.ru" },
  internal: { prefix:"certissue-", base:".internal" }
};
const Bo = "/internal/cert";

// strip prefix+base from a hostname for the given side; null if it doesn't match
function uc(host, side){
  const {prefix,base} = lc[side];
  return host.startsWith(prefix) && host.endsWith(base)
         && host.length > prefix.length + base.length
       ? host.slice(prefix.length, host.length - base.length)   // = the token, e.g. "bv5kavo6"
       : null;
}

function Li(host = location.hostname){ return uc(host,"internal") !== null; }   // "are we on the internal host?"

function Hd(host = location.hostname){                     // external token -> internal hostname
  const token = uc(host,"external");
  const {prefix,base} = lc.internal;
  return `${prefix}${token ?? "<token>"}${base}`;           // certissue-<token>.internal
}
```

So for `portal-bv5kavo6.beeca.avitoctf.ru`, `uc(...,"external")="bv5kavo6"` and
`Hd()="certissue-bv5kavo6.internal"`. `Li()` is **false** on the portal, **true** only on the internal host.

### 2.2 Role logic (offset 153080)

```js
const ic = "#/operator";
function Wd(){ return Li() || location.hash === ic ? "operator" : "user"; }
```

But `App` (`Qd`) **downgrades the hash-based operator role on the external host** (offset 153647):

```js
const m = Li();                                    // false on portal
const h = () => {
  const k = !m && location.hash === ic;            // "operator preview" on an EXTERNAL host
  o(m || k ? "operator" : "user");
  if (k) return setTimeout(() => {                 // ...for only ~70 ms
    history.replaceState(null,"",`${location.pathname}${location.search}`);   // strips #/operator
    o("user");
  }, 70);
};
```

**Meaning:** visiting `#/operator` on the portal only *flashes* the operator UI for 70 ms and then reverts to
`user` and deletes the hash. Genuine, persistent operator mode requires actually being on
`certissue-…​.internal` (`Li()===true`). The "Проследить передачу во внутренний контур" button
(`Ad.s = () => { location.hash = "/operator"; }`) triggers exactly this preview.

### 2.3 Operator console `Vd` (offset 150679)

```js
function Vd({showToast}){
  const uuid0 = new URLSearchParams(location.search).get("uuid") || "";
  const n = Li() ? location.host : Hd();            // console host: real host if internal, else DERIVED certissue-<token>.internal
  // log seeds:
  //   `[operator] console host: ${n}`
  //   `[operator] action endpoint: https://${n}${Bo}?uuid=<id>&action=approve|decline`
  const s = async (action) => {                      // action = "approve" | "decline"
    const m = uuidInput.trim();
    const h = await fetch(`${Bo}?uuid=${encodeURIComponent(m)}&action=${action}`,
                          {method:"POST", credentials:"same-origin"});
    const p = await h.json().catch(()=>({}));
    // ok -> `[approve] ok: status=${p.status}` ; toast `Заявка ${p.status}.`
  };
  // UI: <input placeholder="uuid заявки"> + buttons "Аппрувнуть"(approve) / "Отклонить"(decline)
  // hive-side seal renders queen-seal "approver"
}
```

**Critical subtlety:** the *printed* action endpoint is the absolute
`https://certissue-<token>.internal/internal/cert?...`, but the **actual `fetch` uses the relative `Bo`**
(`"/internal/cert"`), i.e. **same-origin**. Therefore the approve/decline POST only reaches the real issuer
when the browser is already on the internal origin. A portal user pressing "Аппрувнуть" would hit
`portal-…avitoctf.ru/internal/cert` (not the issuer). The approver is a client operating on the internal
host — that is where an injected script (see §4) would land its same-origin POST.

There is **no CSRF token, no auth header, no role parameter** on `/internal/cert` — only cookie/origin +
`uuid` + `action`. `uuid` is free-text input; nothing ties it to the operator's own enrollment.

---

## 3. Enrollment / CN state machine

`enrollment` object fields observed client-side: **`uuid, cn, status, serial, fingerprint, not_after`**
(status card `$d`, offset 144852). Statuses: **`guest`** (no enrollment / default), **`pending`**, **`issued`**.

Status → note map `Fd` (offset ~144150):
```
pending: "Заявка отправлена. Обновите страницу позже, чтобы проверить статус аппрува."
issued : "Сертификат выпущен. Скачайте .p12 и импортируйте его в браузер; пароль: beeca."
guest  : "Войдите и создайте пер…"   (login prompt)
```

CN is only ever **displayed**, never sent:
- `Dd` hero (offset 143405): `v.jsxs("div",{className:"queen-seal",children:["CN=", l||"—"]})` where `l = enrollment?.cn`.
- `$d` status card: `<dt>CN</dt><dd>{enrollment?.cn ?? "—"}</dd>` (also Serial, Fingerprint, "Действителен до"=`not_after`).

Policy strings (in the `Ad` log-lines array `c`, offset 149776 and 149109):
```
`[portal] session active for ${e.email}`  ||  "[portal] anonymous visitor detected"
"[queue] one session = one enrollment request"
"[policy] CN is derived from verified SSO identity"
"[policy] manual approval required before bundle download"
```

**Flow:** enroll (`POST /api/enroll`, no body) → server derives CN from the SSO identity and returns
`{serial,cn,status}` → `status==="pending"` waits for manual operator approval → once `issued`,
`GET /api/cert` returns `beeca-client.p12` (pw `beeca`). **The client has no field, header, or body that
sets or echoes CN** — CN control, if any, must be attacked server-side (SSO display-name/email → CN
mapping), not in this bundle.

---

## 4. Feedback flow + the XSS sink

`Ud` (offset 146157):
```js
const [request_id, setRequestId] = useState(me?.enrollment?.uuid ?? "");   // editable input "Номер заявки"
const [message,   setMessage]    = useState("Здравствуйте! Прошу ускорить рассмотрение моей заявки на сертификат."); // editable
// on send:
const w = await (await fetch("/api/feedback",{...,body:JSON.stringify({request_id,message})})).json();
s(w);   // store response
```
`request_id` defaults to our own enrollment uuid **but is a free-text `<input>`** → we may reference *any*
uuid.

**The sink** (offset 147817, feedback-done view):
```js
v.jsx("p",{className:"card-note",children:"Текст вашего обращения:"}),
v.jsx("div",{className:"feedback-echo", dangerouslySetInnerHTML:{ __html: o.message }})   // o = w = server response
```
The echoed HTML is **`o.message`, the server's response `message`**, rendered unescaped. In this bundle it
renders in **the submitter's own** "feedback-done" card (self-XSS locally). The exploit value depends on the
server: if the server **stores** the feedback and a **moderator/operator view renders the same `message`
with the same unsanitized `dangerouslySetInnerHTML`**, then attacker-controlled `message` becomes
**stored XSS in the moderator's browser**. Because the operator works on the internal origin (§2), injected
JS there can fire the same-origin `POST /internal/cert?uuid=<ours>&action=approve`. The `message` is fully
attacker-controlled (default text is editable). Example payload:
`<img src=x onerror="fetch('/internal/cert?uuid=<OUR_UUID>&action=approve',{method:'POST',credentials:'same-origin'})">`.

Flavor hint (offset 147817, just above the sink):
`"(на пчелином: ханипот, пчёлы и так связываются по пчелиным каналам)"` — "honeypot; bees talk over bee
channels", i.e. the moderator/agent reads your feedback.

---

## 5. Hidden content sweep (what is NOT there)

- **No Google OAuth client id / GSI / `apps.googleusercontent.com`.** SSO is entirely server-side; the
  client only has `<a href="/login">Войти через Google</a>`. So no client-side SSO parameters to tamper.
- **No hardcoded tokens/secrets/API keys, no bearer/authorization headers, no base64/hex blobs.** The only
  long alnum strings are React internal property names (`SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED`
  etc.). The single embedded secret is the p12 **password `beeca`** (already public in UI text).
- **No dev/debug/feature flags, no `import.meta.env` / `VITE_*` vars, no commented endpoints, no
  sourceMappingURL.**
- **Only one client route:** `#/operator`. No admin route, no other API paths.
- All app fetches enumerated in §1; all are same-origin cookie-auth (no CSRF tokens anywhere).

---

## 6. Leads for the live agents (ranked)

1. **Stored XSS / prompt-injection into the moderator via `POST /api/feedback` `message`.** The message is
   round-tripped and rendered with `dangerouslySetInnerHTML:{__html:o.message}` and is fully
   attacker-controlled. If the moderator's review view echoes it the same way, JS runs in the moderator's
   context — and the moderator works on the **internal origin**, where the same-origin
   `POST /internal/cert?uuid=<ours>&action=approve` approves your enrollment (drive to `issued`, then pull
   `p12`). If the moderator is an LLM/agent ("vibecoder bees" / "Первопромпт" / honeypot flavor),
   plain-text prompt injection in `message` to *approve / issue* is the same door. **Top web+logic vector.**
   Probe: does the operator/moderation view reflect a submitted `message` unescaped? Can `request_id`
   reference an arbitrary uuid (it's a free input)?

2. **`/internal/cert` authorization model.** The approve/decline call carries **no CSRF token and no role
   arg** — just cookie/origin + `uuid` + `action`, and `uuid` is arbitrary. Anything that lets you execute
   same-origin on `certissue-<token>.internal` (lead 1, or an SSRF/proxy that forwards to it) can approve
   any enrollment. Probe: is `/internal/cert` reachable from the portal origin at all (likely 404/blocked)?
   Does any portal endpoint proxy inward to `certissue-bv5kavo6.internal`? The internal hostname is fully
   derived client-side (`Hd()` → `certissue-bv5kavo6.internal`).

3. **Server-side CN control (`CN is derived from verified SSO identity`).** The client cannot influence CN
   (`/api/enroll` has no body/CSR — server keygen). So a `CN=admin` cert must come from a differential in
   the server's SSO-identity → CN mapping (Google display-name/email injection, extra RDNs, null-byte
   `admin\x00…`, PrintableString vs UTF8String / RDN-order parsing gap between issuance and the admin host's
   `$ssl_client_s_dn_cn` check), or from getting the operator/agent to issue `CN=admin` via lead 1. Not
   client-exploitable from the bundle — hand to server-side probing.

Secondary: `GET /api/cert` returns the `beeca-client.p12` (pw `beeca`) only when `status==="issued"` — pull
it once any enrollment is approved to inspect the CA chain / serial policy for a self-issuance oracle.
