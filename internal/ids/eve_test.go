package ids

import (
	"testing"
	"time"
)

func TestParseEveLine(t *testing.T) {
	line := `{"timestamp":"2026-11-01T09:04:19.123456+0800","flow_id":1234,"in_iface":"eth0","event_type":"alert",` +
		`"src_ip":"10.1.0.5","src_port":51515,"dest_ip":"10.1.0.8","dest_port":445,"proto":"TCP",` +
		`"alert":{"action":"allowed","gid":1,"signature_id":2024217,"rev":3,` +
		`"signature":"ET EXPLOIT Possible ETERNALBLUE Probe MS17-010","category":"Attempted Administrator Privilege Gain","severity":1},` +
		`"app_proto":"smb","payload_printable":"..."}`
	ev, ok := ParseEveLine([]byte(line))
	if !ok {
		t.Fatal("alert not parsed")
	}
	if ev.SrcIP != "10.1.0.5" || ev.DestIP != "10.1.0.8" || ev.DestPort != 445 || ev.SignatureID != 2024217 ||
		ev.Severity != 1 || ev.AppProto != "smb" || ev.Category != "Attempted Administrator Privilege Gain" {
		t.Errorf("got %+v", ev)
	}
	if want := time.Date(2026, 11, 1, 1, 4, 19, 123456000, time.UTC); !ev.Time.Equal(want) {
		t.Errorf("time = %v, want %v", ev.Time, want)
	}

	for _, other := range []string{
		`{"timestamp":"2026-11-01T09:04:19.123456+0800","event_type":"flow","src_ip":"10.1.0.5"}`,
		`{"event_type":"stats","stats":{}}`,
		`not json`,
	} {
		if _, ok := ParseEveLine([]byte(other)); ok {
			t.Errorf("%s should be ignored", other)
		}
	}
}
