# 006 — C2-beacon false positives on multicast / broadcast traffic

## Problem

The probe's network analyzer raised "C2 heartbeat" incident #3 for
`192.168.140.111 → 239.255.255.250:1900` every ~24s. That is SSDP (UPnP
discovery) multicast, sent by printers, TVs and Windows hosts and delivered to
every host on the LAN. Beacon and off-hours exfil analysis ran on any flow
whose destination was not `Internal()`, and multicast / broadcast addresses are
not `Internal()`.

## Fix

Feed only flows to public destinations into beacon / exfil analysis: replace
`!Internal(dst)` with `!SpecialUseAddr(dst)`. The special-use list already
covers `224.0.0.0/4`, `240.0.0.0/4` (incl. `255.255.255.255`) and `ff00::/8`.
Intel matching on flows is unchanged.

## Rollout

The analyzer runs in `safe-probe`, so the fix needs the new probe binary in the
management center's `downloads/` and a re-run of the probe installer on each
probe host (probes have no online upgrade).

## Acceptance

- `TestBeacon` includes periodic flows to `239.255.255.250:1900` and
  `255.255.255.255`; neither is reported (failed before the fix).
- After rollout, no new beacon alerts for SSDP / mDNS destinations.
