# 009 Network IDS stopped: judge by eve.json activity, not by alerts

Follows 008 (probe health alerts).

## Problem

008 raised `ids_silent` when a probe sent no IDS events for 15 minutes. IDS
events are Suricata rule hits, which are bursty: a quiet network produces none,
so the alert fired as a false positive (alert #91 on 2026-11-04, minutes after
deploy). The 14-hour "outage" that motivated 008 was the probe host being shut
down (Agent reported "stopped" at the same second), not Suricata failing.

## Change

- The probe tracks when it last read new lines from `eve.json` (any record type:
  stats every 8 s by default, flow, dns, alerts), starting from probe start, and
  sends `eve_idle` (seconds) in its periodic config request (every 15 s). Probes
  without `-eve` omit it.
- The server converts it with its own clock (`now - eve_idle`, immune to probe
  clock skew) into `nodes.ids_seen`, now meaning "eve.json last seen growing".
- `ids_silent` fires when an online probe's `ids_seen` > 0 is older than 15
  minutes. `ids_seen` <= 0 (older probe, or no `-eve`) is not checked.
- Removed: backfill from stored IDS events, and updating `ids_seen` on IDS
  reports.

The column keeps its name: adding a new one and abandoning `ids_seen` would
break `CopyFrom` (SQLite -> PostgreSQL copies every source column).

## Acceptance

- Store test: a quiet network with eve.json still growing raises nothing;
  eve.json not growing for 15 minutes raises `ids_silent` once; growth resumes
  -> auto-acknowledged; probes that never report eve are not checked.
- Server test: config request with `eve_idle` updates `ids_seen`.
- Deployed; after the probe on mx is updated, office reports `ids_seen` within
  15 s and #91 is auto-acknowledged.
