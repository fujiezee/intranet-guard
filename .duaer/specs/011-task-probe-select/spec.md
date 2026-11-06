# 011 Scan task: probe dropdown

## Problem

The new scan task dialog takes the probe ID as free text, so a typo creates a
task no probe ever picks up.

## Change

- Console: the probe ID field becomes a filterable dropdown of enrolled, active
  probes, refreshed each time the dialog opens, with the first probe preselected.
- Typing an ID stays possible, as in the honeypot dialog: without mTLS, probes
  run without enrolling and do not appear in the node list.

The task API is unchanged.

## Acceptance

- The dialog lists active probes only; revoked probes and agents are excluded.
- A task is created with the selected probe.
- `check:i18n`, `check:guide`, `check:refs`, `build` pass.
