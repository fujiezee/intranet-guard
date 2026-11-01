# PG_DSN 指向一个可以创建 schema 的 PostgreSQL 库；每个测试使用独立 schema，结束后删除。
PG_DSN ?= postgres://safe@127.0.0.1:54329/safe_test?sslmode=disable
# CH_URL 指向 ClickHouse HTTP 接口；每个测试创建独立的库，结束后删除。
CH_URL ?= clickhouse://default:@127.0.0.1:8123

.PHONY: test test-pg test-ch build web

test:
	go test ./...

test-pg:
	SAFE_TEST_PG_DSN='$(PG_DSN)' go test -count=1 ./...

test-ch:
	SAFE_TEST_CH_URL='$(CH_URL)' go test -count=1 ./...

web:
	cd web && npm install && npm run build

build: web
	go build -o bin/safe-server ./cmd/server
	for t in linux/amd64 linux/arm64; do \
		GOOS=$${t%/*} GOARCH=$${t#*/} go build -o bin/safe-probe-$${t%/*}-$${t#*/} ./cmd/probe; \
		GOOS=$${t%/*} GOARCH=$${t#*/} go build -o bin/safe-agent-$${t%/*}-$${t#*/} ./cmd/agent; \
	done
