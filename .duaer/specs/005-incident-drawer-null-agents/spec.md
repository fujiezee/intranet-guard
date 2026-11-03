# 005 — Incident detail drawer is blank for network-only incidents

## Problem

Clicking an incident whose host has no agent (e.g. a C2-beacon incident raised
by a probe for `192.168.140.111`) slides the detail drawer open with no
content. `AgentIDsForIP` returns a nil slice when no agent reported that
address, so `GET /api/v1/incidents/{id}` sends `"agents": null`; the console
reads `detail.agents.length`, throws, and the drawer body never renders.

## Fix

- `store.AgentIDsForIP` returns `[]string{}` instead of nil, matching
  `IncidentNotes` / `IncidentAlerts`.
- `Incidents.vue` reads `detail.agents?.length` as a guard.

## Acceptance

- `TestIncidentDetailWithoutAgent`: a network-only incident's detail has
  `agents`, `alerts`, `events`, `notes` as JSON arrays (failed before the fix).
- On the console, opening the incident for a host without an agent shows the
  timeline and the note "this address has no Agent, only network-side alerts".
