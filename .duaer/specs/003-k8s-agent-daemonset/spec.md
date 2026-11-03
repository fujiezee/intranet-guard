# 003 — Host agent on Kubernetes (container image + DaemonSet)

## Goal

Run `safe-agent` on every node of a Kubernetes cluster so that process
execution, container-escape attempts, file-integrity changes and webshells on
the nodes and their pods are audited by the existing management center. Today
the agent ships only as a systemd unit; the cluster has no coverage.

## Scope

- A container image for `safe-agent` (linux/amd64), pushed to the user's
  private registry.
- A DaemonSet manifest and a one-time enrollment Secret that make the agent
  run on all nodes (including control-plane) and enroll to the management
  center at `https://47.117.27.183:8443` over mTLS.
- English operator docs: build, push, create an enrollment token, apply.

Out of scope: network probe on the cluster (separate per-segment work),
Kubernetes-API-based inventory, Helm chart, arm64.

## Why no code change

The agent already understands containers: it reads `/proc/<pid>/cgroup` for the
container ID and Pod UID (`internal/agent/container.go`) and maps the UID to a
name via `/var/log/pods` (`procmon_linux.go`). Escape detection rules already
exist (`cmdrules.go`: `nsenter -t 1`, `mount /dev`, `release_agent`,
`/proc/sysrq-trigger`, `core_pattern`, `chroot /host`). So node coverage is a
packaging problem:

- `hostPID: true` makes the container's `/proc` show every host and pod
  process — process monitoring, cgroup→Pod mapping and escape detection all
  work unmodified.
- A read-only hostPath mount of `/var/log/pods` resolves Pod UID → namespace/name.
- Read-only hostPath mounts of the FIM dirs let FIM watch the node host's
  `/etc`, `/root`, `/home`, cron.

## Acceptance

- `make docker-agent REGISTRY=<reg> VERSION=<v>` builds and (with `push`) pushes
  an amd64 image.
- Applying `deploy/k8s/` with a valid enrollment token brings up one agent pod
  per node; each appears in the console node list as `agent` with the node's
  name and stays `online`.
- Killing/altering `/etc/passwd` or running an escape pattern on a node raises
  the corresponding alert in the console.
- Pod restart keeps the node enrolled (cert persists on the node's hostPath);
  no token is consumed on restart.

## Decisions

- **Node ID = node name** via the downward API (`spec.nodeName`), not the pod's
  random hostname.
- **State on hostPath** `/var/lib/safe-agent` so each node enrolls once and
  keeps its certificate across pod restarts.
- **Enrollment token** is multi-use: `max_uses >= node count`. Stored in a
  Secret, consumed once per node, ignored after enrollment.
- **Privileged + root**: required to read other pods' `/proc`, `/etc/shadow`
  and to run response actions (kill process). Documented as such.
- **FIM `/etc` mount**: the agent authenticates with the internal CA stored in
  its state dir and reaches the server by IP, so overmounting the container's
  `/etc` read-only from the host does not affect connectivity.
