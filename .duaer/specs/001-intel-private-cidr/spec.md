# 001 Reject internal networks in threat intel

## Problem

`store.ParseIndicator` drops private / loopback single IPs but accepts any CIDR with a
prefix length of 8 or more. Public feeds such as FireHOL level1 list bogon ranges
(`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, …), so subscribing to one makes every
intranet address an intel hit.

## Scope

- One rule for "internal or special-use" networks in `netintel`: private, loopback,
  unspecified, CGNAT, link-local, benchmarking, IETF protocol assignments, multicast,
  reserved (IPv4 and IPv6). A CIDR is rejected if it overlaps any of them.
- Import (manual text and feeds) drops IPs and CIDRs matching the rule.
- Matching (`netintel.NewIntel`) skips them too, so indicators stored before the fix
  stop matching without waiting for a feed refresh.

Out of scope: deleting already-stored rows (feeds replace theirs on the next fetch;
manual rows can be deleted in the console). Documentation ranges (TEST-NET-1/2/3) stay
accepted: tests and examples use them as stand-ins for public addresses.

## Acceptance

- FireHOL level1 parses with zero internal / special-use prefixes; its public prefixes
  are kept.
- `10.1.2.3` no longer matches an Intel built from a list containing `10.0.0.0/8`.
- `go test ./...` passes on SQLite, PostgreSQL and ClickHouse; vet and gofmt clean.
