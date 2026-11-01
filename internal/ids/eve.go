// Package ids 解析 Suricata EVE JSON 输出。
package ids

import (
	"encoding/json"
	"time"

	"safe/internal/model"
)

type eveRecord struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	AppProto  string `json:"app_proto"`
	Alert     *struct {
		Action      string `json:"action"`
		SignatureID int64  `json:"signature_id"`
		Signature   string `json:"signature"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
	} `json:"alert"`
}

// ParseEveLine 解析一行 EVE JSON；只处理 alert 类型，其余（flow、dns、http、stats 等）返回 false。
func ParseEveLine(line []byte) (model.IDSEvent, bool) {
	var r eveRecord
	if err := json.Unmarshal(line, &r); err != nil || r.EventType != "alert" || r.Alert == nil {
		return model.IDSEvent{}, false
	}
	ts, err := time.Parse("2006-01-02T15:04:05.999999-0700", r.Timestamp)
	if err != nil {
		ts, err = time.Parse(time.RFC3339Nano, r.Timestamp)
		if err != nil {
			ts = time.Now()
		}
	}
	sev := r.Alert.Severity
	if sev < 1 {
		sev = 3
	}
	return model.IDSEvent{
		Time: ts.UTC(), SrcIP: r.SrcIP, SrcPort: r.SrcPort, DestIP: r.DestIP, DestPort: r.DestPort,
		Proto: r.Proto, AppProto: r.AppProto, SignatureID: r.Alert.SignatureID, Signature: r.Alert.Signature,
		Category: r.Alert.Category, Severity: sev, Action: r.Alert.Action,
	}, true
}
