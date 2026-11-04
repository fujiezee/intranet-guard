# 010 Asset names: NetBIOS, agent hostname, manual name

## Problem

All 62 assets on the office network have an empty hostname. The scanner only
tries reverse DNS (PTR), and the office router publishes no PTR records for DHCP
clients. Most hosts are Windows (37 with 135/445 open, 33 with 139 open).

## Change

- Scanner: when reverse DNS returns nothing, send a NetBIOS node status query
  (NBSTAT, UDP 137) and use the unique workstation name (suffix 0x00). No
  credentials, no router dependency. Non-ASCII names are decoded as GBK
  (Windows OEM code page in Chinese locales). Name lookups run in parallel
  (32 at a time) instead of one by one.
- Assets API: `agent_hostname` is the hostname reported by an agent whose IPs
  include the asset IP; `name` is a manual name set by an admin (new column
  `assets.name`, edited with importance / owner / tags).
- Console: assets list, asset drawer and dashboard show
  name > agent hostname > scanned hostname; search matches all three.

Scanned hostnames still never overwrite a known name with an empty one.

## Acceptance

- Unit tests: NBSTAT query encoding, response parsing (unique vs group names,
  truncated / malformed packets, GBK), end-to-end against a local UDP responder.
- Store / API tests: manual name saved and returned; agent hostname attached.
- `go test ./...`, `check:i18n`, `check:guide`, `check:refs`, `build` pass.
- Deployed; after the mx probe is updated and the office segment rescanned,
  most Windows hosts show a name.
