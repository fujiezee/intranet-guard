#!/bin/sh
# 在本机启动开发 / 单机部署用的 ClickHouse：数据在 data/clickhouse，只监听 127.0.0.1:8123（HTTP）/ 9000（native）。
# 用户与密码见 data/clickhouse/users.xml；生产环境请按 ClickHouse 官方文档部署独立集群。
set -eu
DIR=$(cd "$(dirname "$0")/.." && pwd)/data/clickhouse
mkdir -p "$DIR/data" "$DIR/tmp" "$DIR/user_files" "$DIR/format_schemas" "$DIR/logs"
[ -f "$DIR/users.xml" ] || { echo "missing $DIR/users.xml" >&2; exit 1; }
cd "$DIR"
exec clickhouse server -- \
  --path="$DIR/data/" --tmp_path="$DIR/tmp/" --user_files_path="$DIR/user_files/" \
  --format_schema_path="$DIR/format_schemas/" \
  --user_directories.users_xml.path="$DIR/users.xml" \
  --logger.log="$DIR/logs/server.log" --logger.errorlog="$DIR/logs/error.log" --logger.level=warning \
  --listen_host=127.0.0.1 --http_port=8123 --tcp_port=9000 \
  --mysql_port=0 --postgresql_port=0 --interserver_http_port=0
