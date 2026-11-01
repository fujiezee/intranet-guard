# PG_DSN 指向一个可以创建 schema 的 PostgreSQL 库；每个测试使用独立 schema，结束后删除。
PG_DSN ?= postgres://safe@127.0.0.1:54329/safe_test?sslmode=disable
# CH_URL 指向 ClickHouse HTTP 接口；每个测试创建独立的库，结束后删除。
CH_URL ?= clickhouse://default:@127.0.0.1:8123

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
AGENT_VERSION_FLAG = -X safe/internal/agent.Version=$(VERSION)

.PHONY: test test-pg test-ch build web release

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

# 生成一键安装包：dist/safe-<版本>-linux-<架构>.tar.gz，解压后 sudo ./install.sh
release: web
	rm -rf dist && mkdir -p dist/downloads
	for t in linux/amd64 linux/arm64; do \
		os=$${t%/*}; arch=$${t#*/}; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags='-s -w $(AGENT_VERSION_FLAG)' -o dist/downloads/safe-agent-$$os-$$arch ./cmd/agent; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags='-s -w' -o dist/downloads/safe-probe-$$os-$$arch ./cmd/probe; \
	done
	for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=windows GOARCH=$$arch go build -trimpath -ldflags='-s -w $(AGENT_VERSION_FLAG)' -o dist/downloads/safe-agent-windows-$$arch.exe ./cmd/agent; \
	done
	@# 管理中心据此判断节点程序的最新版本，用于控制台升级 Agent
	printf '{"version": "%s"}\n' '$(VERSION)' > dist/downloads/manifest.json
	for arch in amd64 arm64; do \
		d=dist/safe-$(VERSION)-linux-$$arch; mkdir -p $$d; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags='-s -w -X safe/internal/server.Version=$(VERSION)' -o $$d/safe-server ./cmd/server; \
		cp -R web/dist $$d/web; cp -R dist/downloads $$d/downloads; \
		install -m 755 scripts/install.sh scripts/backup.sh $$d/; \
		tar -czf $$d.tar.gz -C dist safe-$(VERSION)-linux-$$arch; \
	done
	rm -rf dist/downloads
	@# MCP 程序运行在使用者的电脑上，单独发布
	for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
		os=$${t%/*}; arch=$${t#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags='-s -w' -o dist/safe-mcp-$(VERSION)-$$os-$$arch$$ext ./cmd/mcp; \
	done
	@ls -lh dist/*.tar.gz
