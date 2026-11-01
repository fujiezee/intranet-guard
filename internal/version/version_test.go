package version

import "testing"

func TestOlder(t *testing.T) {
	for _, tc := range []struct {
		cur, latest string
		want        bool
	}{
		{"0.3.0", "0.9.0", true},
		{"0.9.0", "0.9.0", false},
		{"0.10.0", "0.9.0", false}, // 按数字而不是字符串比较
		{"0.9.0", "0.10.0", true},
		{"v0.9.0", "0.9.1", true},
		{"0.9.0-3-gabc123", "0.9.1", true},
		{"1.0", "1.0.1", true},
		{"dev", "0.9.0", false}, // 开发构建不自动升级
		{"0.9.0", "ci", false},
		{"", "0.9.0", false},
	} {
		if got := Older(tc.cur, tc.latest); got != tc.want {
			t.Errorf("Older(%q, %q) = %v, want %v", tc.cur, tc.latest, got, tc.want)
		}
	}
}
