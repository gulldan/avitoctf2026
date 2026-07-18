# Brainwash (Avito CTF 2026, SPbCTF / @abreeva) — tasks 13/14/15 SOLVED

Target: `brainwash-ztkaw810.avitoctf.ru` → launcher → Aim instance (uvicorn :80) on a
per-player k3s node. Everything runs in the `brainwash-mlops` namespace of a k3s cluster.

## The unlock the prior sessions missed
The whole thing was "blocked" for many sessions because the Aim AimQL RCE (CVE-2024-2195)
needs ≥1 Run to exist, and the only write channel is the Aim **remote-tracking server**.
Prior work only ever tested that server on its **default port `:53800`** (firewalled) and
declared it dead. It is actually exposed on a **Kubernetes NodePort `:30800`** — a full
port scan of 30000-32767 found it (`{"status":"OK"}`). That single fact unlocks all three.

## Task 13 — RCE / read files  →  `avito{3Xperim3n7s_aR3_unREL1aBl3_BU7_rcE_N3V3R_liEs}`
1. Self-seed a Run over the tracking NodePort: `aim.Run(repo="aim://<host>:30800")` → `num_runs=1`.
2. Fire the AimQL RestrictedPython escape on `:80`:
   `q = run.db.runs().session.bind.dialect.dbapi.datetime.sys.modules["os"].system("<cmd>") or 1`
   (append `or 1` + `&limit=1` so the search returns on the first run — O(1), not O(runs)).
3. Root FS is read-only, so the classic static-files exfil fails. Exfil instead by writing
   the loot into an **aim Run param** (`Run(repo='/data/repo'); r['out']=...`) and reading it
   back via `/api/runs/{id}/info`. `/flag.txt` (k8s secret `flag1`) = the flag.
   Same shot leaked: pod `webapp`, ns `brainwash-mlops`, k3s, SA **`ci-runner`**.
   Tooling: `rce_exec.py` (reusable RCE→exfil shell).

## Task 14 — "look at the root, peek into each one"  →  `avito{wHa7_PaS5Es_For_trUth_1S_Eph3mERaL}`
`ci-runner` RBAC: `pods get/list` + **`pods/ephemeralcontainers patch`**.
- Enumerate every pod → secret `flag2` is mounted `/flag.txt` in the **cert-agent** pod
  (SA `cert-manager-sa`). Can't read secrets (403).
- Inject a PodSecurity-`restricted`-compliant **ephemeral container** into cert-agent, mount
  the `flag2` volume, dump it to the container **termination message** (readable via
  `pods/get` — no exec/logs needed). = flag2. (`pod_all.py`)

## Task 15 — cluster takeover  →  `avito{Learn_Th3_ORCh3S7r4TioN_Not_The_ind0ctr1n4t1on}`
1. Grab the **cert-manager-sa** token (ephemeral container mounting its projected SA volume).
   cert-manager-sa RBAC: **create + approve CSRs** for `kubernetes.io/kube-apiserver-client`.
2. Mint a client cert via CSR. A custom admission webhook `csr-subject.brainwash.local`
   forces the subject: **`CN=proxyman, O=node-proxymen`** (system:masters is blocked).
   Create → self-approve → fetch signed cert. (`pod_mint.py`; EC key to keep payload small.)
3. `proxyman`/`node-proxymen` RBAC = **`nodes/proxy get`** (kubelet access). Talk to the
   kubelet: `/pods` shows **kube-system/log-collector** = `privileged:true`, `runAsUser:0`,
   hostPath **`/`** mounted at `/host`.
4. Kubelet exec (WebSocket) into log-collector = **root on the node**. NOTE: exec via the
   apiserver `nodes/proxy` path strips the query string, so hit the **kubelet directly on
   `<hostIP>:10250`** with the proxyman client cert (authorized as `nodes/proxy get`).
   `cat /host/flag.txt` = flag3. Also grabbed `/host/etc/rancher/k3s/k3s.yaml`
   (cluster-admin `system:masters` kubeconfig) = literal total domination. (`pod_exec.py`)

## Key scripts (task13/)
- `rce_exec.py` — RCE→exfil shell over AimQL (append `or 1`, limit=1, /tmp gate for idempotency)
- `pod_all.py` (flag2), `pod_gettoken.py`/`pod_sa.py` (cert-manager-sa token)
- `pod_mint.py` (mint proxyman cert), `pod_exec.py` (direct-kubelet WebSocket exec = node root)
- discipline: seed exactly ONE run; deleting/accumulating hundreds of runs OOM-crashes `aim up`.
