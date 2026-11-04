# 007 IDS events: filter-aware empty state

## Problem

The Traffic detection > Events tab filters to high + medium priority by default.
When every stored event is low priority (typical right after Suricata is
connected: ET INFO rules), the table is empty and shows "No events. Check that
the probe reads Suricata output through -eve", which sends the admin to debug a
working probe.

## Change

- With any filter active (priority other than "all", or a source / destination /
  rule ID filter), the empty table says "No events match the filters".
- Only with no filter does it keep the -eve hint.

## Acceptance

- Default view with only low-priority events shows "No events match the filters".
- "All priorities" with no events shows the -eve hint.
- `npm run check:i18n`, `check:refs` and `build` pass.
