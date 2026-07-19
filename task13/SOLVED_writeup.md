# Brainwash (Avito CTF 2026, SPbCTF / @abreeva) — tasks 13/14/15 SOLVED

**Target:** `brainwash-ztkaw810.avitoctf.ru` → launcher → Aim (uvicorn :80) instance on a
per-player k3s node, namespace `brainwash-mlops`.

This is the condensed, command-level cheat sheet for the chain. For the full investigation
narrative (fingerprinting method, the CVE research, and — most useful pedagogically — how the
"port :53800 is dead" conclusion turned out to be a Claude-sandbox egress artifact rather than
a fact about the target) see `task13/brainwash_task131415_writeup.md`. Both files describe the
same solve; this one is the "what to actually type" version.

## Recon — the unlock that prior sessions missed

Fingerprinting (`server: uvicorn`, `/static-files/`, `openapi.json` diffed byte-for-byte
against PyPI `aim==3.29.1`) identified the stack as **Aim** (aimhub.io). Known CVE for that
version: **CVE-2024-2195 / CVE-2025-5321**, an RCE via a `RestrictedPython` sandbox escape in
the AimQL query language. The catch: the malicious predicate only executes while Aim iterates
over an *existing* Run, and this instance boots with `num_runs=0`. Every write endpoint on
port 80 (`aim up`) is read-only (`@check_read_only`), so the only way to create a Run is
Aim's unauthenticated remote-tracking server (`aim server`).

The whole thing was "blocked" for many sessions because that tracking server was tested only
on its **default port `:53800`**, which the Kubernetes Service in front of the pod does not
expose externally — every probe against it (curl, `requests`, the real `aim` SDK, even a
browser WebSocket) came back silent. It is actually exposed on a **Kubernetes NodePort
`:30800`** — found by scanning the full NodePort range (30000–32767), not just the guessed
candidates (53800/8000/8080/43800). `{"status":"OK"}` on `/status/` confirmed it. That single
fact — look at the *whole* NodePort range, not just the app's documented default port —
unlocks all three flags.

## Vulnerability

1. **RestrictedPython escape (AimQL).** The sandbox only blacklists names starting with `_`.
   An attribute-pivot through public attributes reaches `os` anyway:
   `run.db.runs().session.bind.dialect.dbapi.datetime.sys.modules["os"].system(...)`.
2. **Unauthenticated write channel reachable via a non-default NodePort.** Self-seeding a Run
   is the precondition for (1) to ever execute.
3. **Kubernetes RBAC over-grants**, exploited across task14/15: `pods/ephemeralcontainers
   patch` without `exec`/`logs`/`get secrets` still lets you exfiltrate a mounted secret by
   dumping it to the ephemeral container's termination message; `create`+`approve` on CSRs
   lets a low-privilege SA self-issue a client certificate, and a custom admission webhook
   narrows — but does not eliminate — that path.

## Exploitation — 13 → 14 → 15

### Task 13 — RCE / read files → `avito{3Xperim3n7s_aR3_unREL1aBl3_BU7_rcE_N3V3R_liEs}`
1. Self-seed a Run over the tracking NodePort: `aim.Run(repo="aim://<host>:30800")` → `num_runs=1`.
2. Fire the AimQL RestrictedPython escape on `:80`:
   `q = run.db.runs().session.bind.dialect.dbapi.datetime.sys.modules["os"].system("<cmd>") or 1`
   (append `or 1` + `&limit=1` so the search returns on the first run — O(1), not O(runs)).
3. Root FS is read-only, so the classic static-files exfil (copy loot into `aim_ui/build`,
   read via `/static-files/`) only works when the target dir is writable. The reliable exfil
   used here: write the loot into an **aim Run param** (`Run(repo='/data/repo'); r['out']=...`)
   and read it back via `/api/runs/{id}/info`. `/flag.txt` (k8s secret `flag1`) = the flag.
   Same shot leaked: pod `webapp`, ns `brainwash-mlops`, k3s, SA **`ci-runner`**.
   Tooling: `rce_exec.py` (reusable RCE→exfil shell), `exploit.py` (static-files variant).

### Task 14 — "look at the root, peek into each one" → `avito{wHa7_PaS5Es_For_trUth_1S_Eph3mERaL}`
`ci-runner` RBAC (checked via `pod_rbac.py`): `pods get/list` + **`pods/ephemeralcontainers
patch`** — but no `exec`, no `logs`, no `get secrets`.
- Enumerate every pod (`pod_all.py`) → secret `flag2` is mounted `/flag.txt` in the
  **cert-agent** pod (SA `cert-manager-sa`). Reading the secret object directly is 403.
- Since `ephemeralcontainers patch` is the one write verb available, use exactly that: inject
  a PodSecurity-`restricted`-compliant **ephemeral container** into cert-agent, mount the
  `flag2` volume read-only, and have it dump the file to the container's **termination
  message** — readable via plain `pods/get` (no exec/logs needed, so no extra RBAC required).

### Task 15 — cluster takeover → `avito{Learn_Th3_ORCh3S7r4TioN_Not_The_ind0ctr1n4t1on}`
1. Same ephemeral-container trick, but mounting cert-agent's own projected SA-token volume
   this time → steal the **cert-manager-sa** token (`pod_sa.py`).
   `cert-manager-sa` RBAC: **create + approve CSRs** for signer
   `kubernetes.io/kube-apiserver-client`.
2. First attempt: CSR with `O=system:masters` — the obvious path to cluster-admin. Blocked: a
   custom admission webhook (`csr-subject.brainwash.local`) force-rewrites the subject of any
   CSR it admits to **`CN=proxyman, O=node-proxymen`** (`system:masters` is unreachable this
   way). Create → self-approve (as `cert-manager-sa`) → fetch the signed cert anyway — it's
   still a working client identity, just not admin. (`pod_mint.py`, EC key to keep the CSR
   payload small.)
3. `proxyman`/`node-proxymen` RBAC = **`nodes/proxy get`** only (kubelet access, nothing more).
   Enough: talk to the kubelet through the API server's node-proxy path, `GET /pods`
   (`pod_kubelet.py`) → **kube-system/log-collector** = `privileged:true`, `runAsUser:0`,
   hostPath **`/`** mounted at `/host` (confirmed with `pod_priv.py`, which dumps
   `securityContext`/`volumes` for every pod on the node).
4. Kubelet exec (WebSocket) into log-collector = **root on the node**. Gotcha: exec via the
   apiserver's `nodes/proxy` path strips the query string (the exec `command=` params are
   lost), so hit the **kubelet directly on `<hostIP>:10250`** with the `proxyman` client cert
   instead — same authorization (`nodes/proxy get`), different transport. (`pod_exec.py`)
   `cat /host/flag.txt` = flag3. Also grabbed `/host/etc/rancher/k3s/k3s.yaml` (cluster-admin
   `system:masters` kubeconfig) — literal total domination beyond the flag itself.

## Flags

- task13: `avito{3Xperim3n7s_aR3_unREL1aBl3_BU7_rcE_N3V3R_liEs}`
- task14: `avito{wHa7_PaS5Es_For_trUth_1S_Eph3mERaL}`
- task15: `avito{Learn_Th3_ORCh3S7r4TioN_Not_The_ind0ctr1n4t1on}`

## Lessons

- Fingerprint → known CVE beats blind fuzzing; matching `openapi.json` against a real PyPI
  wheel gives exact source for free.
- Blacklists on `_`-prefixed names don't stop attribute-pivot escapes — any reachable object's
  public attribute chain can lead to `os`/`sys`.
- Don't trust "port is dead" until you've ruled out that *your own* vantage point (sandboxed
  egress, a corporate proxy, whatever) is the thing that's actually dead — and don't stop at
  an app's documented default port when the real service sits behind a Kubernetes Service:
  scan the whole NodePort range.
- Minimal RBAC verbs still leak data sideways: `ephemeralcontainers patch` without
  `exec`/`logs`/`get secrets` is enough to read any mounted secret via the termination
  message channel.
- An admission webhook that rewrites a CSR's subject narrows privilege escalation, it doesn't
  close it — a "downgraded" certificate can still be the last hop needed to reach the kubelet
  and pivot to node root.
- Discipline: seed exactly ONE run; deleting/accumulating hundreds of runs OOM-crashes `aim up`.

## Key scripts (`task13/`)
- `rce_exec.py` — RCE→exfil shell over AimQL (append `or 1`, limit=1, `/tmp` gate for idempotency)
- `pod_all.py` (flag2), `pod_gettoken.py`/`pod_sa.py` (cert-manager-sa token)
- `pod_mint.py` (mint proxyman cert), `pod_exec.py` (direct-kubelet WebSocket exec = node root)
