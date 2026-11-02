# 002 Recommended threat intel feeds

## Problem

The threat intel list is nearly empty out of the box. The Subscriptions tab offers three
"common public feeds" links, but URLhaus and ThreatFox now return HTTP 410 (abuse.ch
requires a registered key) and Feodo Tracker lists about 5 IPs.

## Decisions (confirmed by the user)

- The management server has internet access.
- Recommended feeds are added by an admin click; nothing is subscribed automatically.

## Scope

- Replace the dead preset links with a verified list of free feeds that work with the
  plain-text parser, each addable with one click (and an "add all" action). Feeds already
  subscribed (same URL) show as added.
- Scale work needed by a few hundred thousand indicators:
  - IP matching against thousands of CIDRs (benchmark; optimize if slow).
  - Measure feed refresh write time and the probe intel download; fix what is too slow.
- Update the user guide.

Out of scope: abuse.ch keyed APIs (URLhaus / ThreatFox auth keys), offline snapshots.

## Acceptance

- Each preset URL was fetched and parsed during development; counts recorded below.
- One click adds a preset; it is fetched and its indicators appear in the list.
- `MatchIP` with ~6,400 real prefixes is well under 1 µs per lookup and matches a
  brute-force scan (longest prefix wins).
- Subscribing to all presets keeps feed refresh and probe intel download practical
  (numbers recorded in delivery.json).
- vet, gofmt, Go tests on SQLite / PostgreSQL / ClickHouse, web checks and build pass.
