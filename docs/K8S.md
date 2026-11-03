# Running the host agent on Kubernetes

The host agent (`safe-agent`) runs as a DaemonSet, one pod per node. It audits
process execution, container-escape attempts, file-integrity changes and
webshells on the nodes and their pods, and reports to the management center
over mTLS — the same way the systemd agent does. It does not talk to the
Kubernetes API, so it needs no ServiceAccount permissions.

Nodes assumed: linux/amd64. Management center: `https://47.117.27.183:8443`.

## 1. Build and push the image

```bash
make docker-agent REGISTRY=registry.internal VERSION=0.1.0 push
```

This builds a static binary into a `scratch` image and pushes
`registry.internal/safe-agent:0.1.0`. Omit `push` to build only.

If nodes pull from a private registry that needs credentials, create a pull
secret and reference it, or configure the nodes' container runtime — standard
Kubernetes, nothing agent-specific.

## 2. Create an enrollment token

In the console: **Node management → generate registration token**, kind
**agent**, **max uses ≥ number of nodes** (each node consumes one use on first
start; pod restarts reuse the stored certificate and consume nothing). Copy the
token string.

```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl -n safe-system create secret generic safe-agent-enroll \
  --from-literal=token='<TOKEN>'
```

The token embeds the server's CA fingerprint, so a wrong server or a
man-in-the-middle is rejected at enrollment.

## 3. Deploy

Set the image in `deploy/k8s/daemonset.yaml` (replace `REPLACE_IMAGE`), then:

```bash
kubectl apply -f deploy/k8s/daemonset.yaml
kubectl -n safe-system rollout status ds/safe-agent
```

Each node appears in the console node list as an `agent` named after the node,
and should go `online` within a minute.

After all nodes are enrolled you may delete the token Secret; the agents keep
their certificates on each node's `/var/lib/safe-agent` hostPath:

```bash
kubectl -n safe-system delete secret safe-agent-enroll
```

## What it needs on the node, and why

| Requirement | Reason |
| --- | --- |
| `hostPID: true` | See every host and pod process via `/proc`; map processes to Pods via `/proc/<pid>/cgroup`; detect container escapes. |
| `privileged`, `runAsUser: 0` | Read other pods' `/proc`, `/etc/shadow`; run response actions (kill a process). |
| hostPath `/var/lib/safe-agent` (rw) | Persist the node's certificate so a pod restart does not re-enroll. |
| hostPath `/var/log/pods` (ro) | Resolve a Pod UID to its namespace/name. |
| hostPath `/etc`, `/root`, `/home`, `/var/spool/cron` (ro) | File-integrity monitoring of node host files (`/etc/passwd`, `sudoers`, `authorized_keys`, cron, …). |
| `hostNetwork: true` | Reach the management center and report the node's real addresses. |

The agent authenticates with the internal CA stored in its state dir and
reaches the server by IP, so mounting the host `/etc` read-only does not affect
connectivity.

## Verify

Raise a test alert from any node, e.g. append a line to `/etc/passwd` on the
host (not in a pod) or run a known escape pattern; the corresponding alert
should appear in the console within the collect interval (default 30s).
