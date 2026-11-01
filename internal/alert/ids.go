package alert

import (
	"fmt"
	"strconv"

	"safe/internal/model"
)

// IDS 把 Suricata 告警转换为平台告警。优先级 3 及以下（多为策略 / 信息类规则）只记录事件，返回 false。
func IDS(assetIP string, ev model.IDSEvent) (DedupAlert, bool) {
	var sev model.Severity
	switch ev.Severity {
	case 1:
		sev = model.SeverityHigh
	case 2:
		sev = model.SeverityMedium
	default:
		return DedupAlert{}, false
	}
	port := 0
	if assetIP == ev.DestIP {
		port = ev.DestPort // 资产是被攻击方时，记录受攻击的端口
	}
	return DedupAlert{
		Alert: model.Alert{
			Type: model.AlertIDS, Severity: sev, IP: assetIP, Port: port,
			Message: fmt.Sprintf("[%s] %s:%d → %s:%d %s（规则 %d，%s）",
				ev.Category, ev.SrcIP, ev.SrcPort, ev.DestIP, ev.DestPort, ev.Signature, ev.SignatureID, ev.Proto),
		},
		DedupKey: "ids:" + strconv.FormatInt(ev.SignatureID, 10) + ":" + ev.SrcIP + ":" + ev.DestIP,
	}, true
}
