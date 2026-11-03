# 004 — Network probe on Kubernetes (per segment)

## Goal

Scan the cluster's networks for open ports, unauthorized services and weak
passwords by running `safe-probe` inside the cluster, one per network segment,
reporting to the existing management center. Complements 003 (per-node host
agent): 003 watches processes/files on each node, 004 watches the network.

## Scope

- A container image for `safe-probe` (linux/amd64) for the private registry.
- A per-segment Deployment manifest (`deploy/k8s/probe.yaml`) with a small
  state volume and `hostNetwork`, enrolling over mTLS.
- `make docker-probe`; docs appended to `docs/K8S.md`.

Out of scope: Suricata traffic IDS sidecar, pod-network scanning (documented as
an option), server-side changes.

## Why no code change

The probe already polls the management center for scan tasks and reports
results; the scan range is assigned console-side, not configured on the probe.
It performs plain TCP connect scans (`internal/scanner`) — no raw sockets — so
it needs no root or privileged, only to sit on the network it must scan.

## Decisions

- **One probe per segment**, a Deployment with `replicas: 1`, not a DaemonSet.
- **`hostNetwork: true`** so the probe scans the node/VPC subnet directly. A
  second probe without hostNetwork can scan the pod network if wanted.
- **State on a ReadWriteOnce PVC** with `strategy: Recreate`, so the probe keeps
  its certificate across restarts/reschedules and does not re-enroll.
- **No privileges**: `runAsUser: 0`, `allowPrivilegeEscalation: false`,
  `capabilities: drop [ALL]`.
- **Enrollment token kind = probe** (distinct from the agent token in 003),
  multi-use if several segments enroll from the same token.
- **-id = segment name**, unique per probe; multiple segments copy the manifest.

## Acceptance

- `make docker-probe REGISTRY=<reg> VERSION=<v> push` builds/pushes an amd64 image.
- Applying `deploy/k8s/probe.yaml` with a valid probe token brings up a probe
  that appears in the console node list as `probe` named after the segment and
  stays `online`.
- After defining the segment's CIDR in the console, hosts and open ports on
  that segment appear as assets; a planted unauthorized service (e.g. open
  Redis) is reported as a vulnerability.
