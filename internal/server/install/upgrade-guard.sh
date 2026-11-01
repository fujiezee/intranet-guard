#!/bin/sh
# safe-agent 升级保护（启动前执行，参数为状态目录）。在线升级后写入 upgrade-pending：
#   第 1 行 启动次数，第 2 行 升级编号，第 3 行 旧版本，第 4 行 新版本，第 5 行 程序路径。
# 新版本首次上报成功后会删除该文件；连续 3 次启动都没删掉（新版本启动即退出），换回旧版本。
S=${1:?state dir}
P="$S/upgrade-pending"
[ -f "$P" ] || exit 0
N=$(($(head -n 1 "$P") + 1))
if [ "$N" -gt 3 ]; then
	B=$(sed -n 5p "$P")
	[ -f "$B.prev" ] && mv -f "$B.prev" "$B"
	mv -f "$P" "$S/upgrade-rolledback"
	echo "safe-agent: new version kept failing to start, rolled back to the previous version" >&2
else
	{ echo "$N"; sed 1d "$P"; } >"$P.tmp" && mv -f "$P.tmp" "$P"
fi
exit 0
