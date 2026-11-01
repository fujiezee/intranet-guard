#!/bin/sh
# 备份管理中心：主库、内部 CA（pki/）、配置与密钥（data/safe.env、ClickHouse 用户配置），可选 ClickHouse 事件。
#
# 用法：scripts/backup.sh [备份目录]            默认 ./backups
# 环境变量：
#   SAFE_HOME          管理中心工作目录（含 safe.db、pki/、data/），默认为本仓库根目录；systemd 部署为 /var/lib/safe
#   SAFE_DB            主库：SQLite 文件路径（相对 SAFE_HOME）或 postgres:// 连接串，默认 safe.db
#   SAFE_EVENTS_DB     设置且 BACKUP_EVENTS=1 时导出 ClickHouse 中的事件（Native 格式）
#   KEEP               保留最近几份备份，默认 14
#
# 备份文件包含 CA 私钥和数据库密码，权限为 0600，请存放到受控位置。恢复步骤见 README。
set -eu

SAFE_HOME=${SAFE_HOME:-$(cd "$(dirname "$0")/.." && pwd)}
DEST=${1:-$SAFE_HOME/backups}
KEEP=${KEEP:-14}
DB=${SAFE_DB:-safe.db}

umask 077
STAMP=$(date +%Y%m%d-%H%M%S)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/safe-$STAMP" "$DEST"
OUT="$WORK/safe-$STAMP"

case "$DB" in
postgres://* | postgresql://*)
	echo "dumping PostgreSQL"
	pg_dump --format=custom --file="$OUT/safe.pgdump" "$DB"
	;;
*)
	case "$DB" in /*) ;; *) DB="$SAFE_HOME/$DB" ;; esac
	echo "backing up SQLite $DB"
	# .backup 在服务运行时也能得到一致的快照
	sqlite3 "$DB" ".backup '$OUT/safe.db'"
	;;
esac

[ -d "$SAFE_HOME/pki" ] && cp -Rp "$SAFE_HOME/pki" "$OUT/pki"
if [ -d "$SAFE_HOME/data" ]; then
	mkdir -p "$OUT/data/clickhouse"
	[ -f "$SAFE_HOME/data/safe.env" ] && cp -p "$SAFE_HOME/data/safe.env" "$OUT/data/"
	[ -f "$SAFE_HOME/data/clickhouse/users.xml" ] && cp -p "$SAFE_HOME/data/clickhouse/users.xml" "$OUT/data/clickhouse/"
fi

if [ "${BACKUP_EVENTS:-0}" = 1 ] && [ -n "${SAFE_EVENTS_DB:-}" ]; then
	# clickhouse://user:pass@host:port/db → HTTP 接口
	rest=${SAFE_EVENTS_DB#*://}
	creds=${rest%%@*}
	hostdb=${rest#*@}
	host=${hostdb%%/*}
	db=${hostdb#*/}
	user=${creds%%:*}
	pass=${creds#*:}
	scheme=http
	case "$SAFE_EVENTS_DB" in clickhouses://*) scheme=https ;; esac
	mkdir -p "$OUT/events"
	for table in host_events ids_events; do
		echo "exporting ClickHouse $db.$table"
		curl -sfS -H "X-ClickHouse-User: $user" -H "X-ClickHouse-Key: $pass" \
			--data-binary "SELECT * FROM $db.$table FORMAT Native" \
			"$scheme://$host/" -o "$OUT/events/$table.native"
	done
fi

ARCHIVE="$DEST/safe-$STAMP.tar.gz"
tar -czf "$ARCHIVE" -C "$WORK" "safe-$STAMP"
chmod 600 "$ARCHIVE"
echo "backup written: $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1))"

# 只保留最近 KEEP 份
ls -1t "$DEST"/safe-*.tar.gz 2>/dev/null | tail -n +$((KEEP + 1)) | while read -r old; do
	rm -f "$old"
	echo "removed old backup: $old"
done
