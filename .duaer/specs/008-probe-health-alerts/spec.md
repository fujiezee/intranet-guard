# 008 Probe health alerts: probe offline and Network IDS stopped

## Problem

When a probe or its Suricata stops, nothing tells the admin. On 2026-11-03 the
office probe stopped sending IDS events at 18:15 and it went unnoticed for 14
hours. Agents already raise "Agent offline" (3 minutes without a heartbeat);
probes have no equivalent, and nothing watches the IDS feed.

## Change

The management server tracks per probe, in `nodes`:

- `last_seen`: last authenticated request from the probe (task polling runs
  every 10 s, so this is a heartbeat; written at most every 30 s per probe).
- `ids_seen`: last IDS report received. `0` = not yet known (backfilled once
  from the newest stored IDS event), `-1` = the probe never sent IDS events
  (no `-eve`), so it is not checked.
- `health`: `''`, `offline` or `ids_silent`.

Every minute (leader only), with a 15-minute threshold (decided by the user):

| Transition | Alert |
|---|---|
| active probe, `last_seen` older than 15 min | `probe_offline`, high |
| probe online, `ids_seen` > 0 and older than 15 min | `ids_silent`, medium |
| IDS reports resume | open `ids_silent` alert acknowledged by `system` |
| probe talks again | open `probe_offline` and `ids_silent` alerts acknowledged by `system` |

One alert per transition (state column, `UPDATE ... RETURNING`), so several
server instances never double-alert. Neither type opens incidents.

No probe change: the probe already polls every 10 s.

Agent offline keeps its 3-minute threshold; loosening it to 15 minutes would
slow an existing detection.

## Acceptance

- Store tests cover: offline alert once, IDS-silent alert once, no IDS check
  for probes that never sent IDS events, backfill from stored events, recovery
  acknowledges the alerts, revoked probes ignored.
- Catalog, alert labels (zh/en), and GUIDE updated; `go test ./...`,
  `check:i18n`, `check:guide`, `build` pass.
- Deployed: the office probe, online with IDS silent since 2026-11-03 18:15,
  raises "Network IDS stopped" within a few minutes of the deploy.
