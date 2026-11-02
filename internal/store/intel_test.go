package store

import (
	"strings"
	"testing"

	"safe/internal/simulate"
)

func TestSimIntelDomainConsistent(t *testing.T) {
	if SimIntelDomain != simulate.IntelDomain {
		t.Fatalf("store.SimIntelDomain %q != simulate.IntelDomain %q", SimIntelDomain, simulate.IntelDomain)
	}
}

func TestParseIntelList(t *testing.T) {
	text := `# abuse.ch feodo
203.0.113.9
198.51.100.0/24   ; 注释
0.0.0.0 evil.com
127.0.0.1	bad.example.org
"1","c2.example.net","online"
10.0.0.5
1.0.0.0/4
10.0.0.0/8 ; FireHOL level1 中的 bogon 网段
172.16.0.0/12
100.64.0.5
fd00::/8
localhost
evil.com
not a valid line !!
`
	got, err := ParseIntelList(strings.NewReader(text), 100)
	if err != nil {
		t.Fatal(err)
	}
	var vals []string
	for _, ind := range got {
		vals = append(vals, ind.Type+":"+ind.Value)
	}
	want := "ip:203.0.113.9 cidr:198.51.100.0/24 domain:evil.com domain:bad.example.org domain:c2.example.net"
	if strings.Join(vals, " ") != want {
		t.Errorf("parsed %v\nwant   %s", vals, want)
	}
	if _, err := ParseIntelList(strings.NewReader(strings.Repeat("203.0.113.1\n203.0.113.2\n203.0.113.3\n", 1)), 2); err == nil {
		t.Error("limit not enforced")
	}
}
