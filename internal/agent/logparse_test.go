package agent

import (
	"testing"
	"time"

	"safe/internal/model"
)

func TestParseAuthLine(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		line  string
		want  model.HostEvent
		count int
	}{
		{
			line:  "Nov  1 09:04:19 web01 sshd[1234]: Accepted publickey for deploy from 10.0.0.8 port 51234 ssh2: RSA SHA256:abc",
			want:  model.HostEvent{Type: model.EventLoginSuccess, User: "deploy", SrcIP: "10.0.0.8", Detail: "ssh publickey"},
			count: 1,
		},
		{
			line:  "Nov  1 09:04:19 web01 sshd[1234]: Failed password for invalid user oracle from 10.0.0.9 port 4444 ssh2",
			want:  model.HostEvent{Type: model.EventLoginFailed, User: "oracle", SrcIP: "10.0.0.9", Detail: "ssh password"},
			count: 1,
		},
		{
			line:  "2026-11-01T09:04:19.123456+08:00 web01 sshd-session[99]: Failed password for root from 10.0.0.9 port 4444 ssh2",
			want:  model.HostEvent{Type: model.EventLoginFailed, User: "root", SrcIP: "10.0.0.9", Detail: "ssh password"},
			count: 1,
		},
		{
			line:  "2026-11-01T09:04:19+0800 web01 sshd[99]: message repeated 3 times: [ Failed password for root from 10.0.0.9 port 4444 ssh2]",
			want:  model.HostEvent{Type: model.EventLoginFailed, User: "root", SrcIP: "10.0.0.9", Detail: "ssh password"},
			count: 3,
		},
		{
			line:  "Nov  1 09:05:00 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx",
			want:  model.HostEvent{Type: model.EventSudo, User: "alice", Detail: "as root: /usr/bin/systemctl restart nginx"},
			count: 1,
		},
		{line: "Nov  1 09:04:19 web01 sshd[1234]: Connection closed by 10.0.0.9 port 4444 [preauth]"},
		{line: "Nov  1 09:04:19 web01 CRON[1]: pam_unix(cron:session): session opened for user root"},
		{line: "garbage"},
	}
	for _, tt := range tests {
		got := ParseAuthLine(tt.line, now)
		if len(got) != tt.count {
			t.Errorf("%q: got %d events, want %d", tt.line, len(got), tt.count)
			continue
		}
		for _, ev := range got {
			if ev.Time.IsZero() {
				t.Errorf("%q: zero time", tt.line)
			}
			ev.Time = time.Time{}
			if ev != tt.want {
				t.Errorf("%q:\n got %+v\nwant %+v", tt.line, ev, tt.want)
			}
		}
	}
}

func TestParseAuthLineYearRollover(t *testing.T) {
	now := time.Date(2027, 1, 1, 0, 5, 0, 0, time.UTC)
	got := ParseAuthLine("Dec 31 23:59:00 h sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2", now)
	if len(got) != 1 || got[0].Time.Year() != 2026 {
		t.Fatalf("got %+v", got)
	}
}
