// Package version 比较节点程序的版本号，用于判断哪些 Agent 需要升级。
package version

import (
	"strconv"
	"strings"
)

// parse 解析 "0.9.0"、"v0.9.0"、"0.9.0-3-gabc123"（git describe）这样的版本号，取前三段数字。
func parse(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// Valid 表示版本号是可比较的正式版本号（开发构建如 "dev" 不是）。
func Valid(v string) bool {
	_, ok := parse(v)
	return ok
}

// Older 判断 cur 是否比 latest 旧。任一方不是正式版本号时返回 false：
// 自动升级只在能确定是"升级"时进行，不会把开发构建或更新的版本"升级"回去（手动升级不受此限制）。
func Older(cur, latest string) bool {
	a, ok1 := parse(cur)
	b, ok2 := parse(latest)
	if !ok1 || !ok2 {
		return false
	}
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
