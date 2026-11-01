// Package alert 定义资产变化的告警规则。
package alert

import (
	"fmt"
	"strings"

	"safe/internal/model"
)

// riskyPorts 是在内网中开放即值得关注的服务：常见未授权访问、明文协议或横向移动通道。
var riskyPorts = map[int]model.Severity{
	23:    model.SeverityHigh, // telnet
	2375:  model.SeverityHigh, // docker API（无认证）
	5900:  model.SeverityHigh, // vnc
	6379:  model.SeverityHigh, // redis
	9200:  model.SeverityHigh, // elasticsearch
	11211: model.SeverityHigh, // memcached
	27017: model.SeverityHigh, // mongodb
	21:    model.SeverityMedium,
	135:   model.SeverityMedium,
	139:   model.SeverityMedium,
	445:   model.SeverityMedium,
	1433:  model.SeverityMedium,
	1521:  model.SeverityMedium,
	3306:  model.SeverityMedium,
	3389:  model.SeverityMedium,
	5432:  model.SeverityMedium,
	5985:  model.SeverityMedium,
}

// NewAsset 为首次发现的主机生成告警，其中的高危端口单独告警。
func NewAsset(a model.Asset) []model.Alert {
	alerts := []model.Alert{{
		Type: model.AlertNewAsset, Severity: model.SeverityMedium, IP: a.IP,
		Message: fmt.Sprintf("发现新主机 %s%s，开放 %d 个端口", a.IP, hostnameSuffix(a.Hostname), len(a.Ports)),
	}}
	for _, p := range a.Ports {
		if sev, ok := riskyPorts[p.Port]; ok {
			alerts = append(alerts, riskyPort(a.IP, p, sev))
		}
	}
	return alerts
}

// NewPort 为已知主机上新开放的端口生成告警。
func NewPort(ip string, p model.Port) model.Alert {
	if sev, ok := riskyPorts[p.Port]; ok {
		return riskyPort(ip, p, sev)
	}
	return model.Alert{
		Type: model.AlertNewPort, Severity: model.SeverityLow, IP: ip, Port: p.Port,
		Message: strings.TrimSpace(fmt.Sprintf("%s 新开放端口 %d/%s %s", ip, p.Port, p.Proto, p.Service)),
	}
}

func riskyPort(ip string, p model.Port, sev model.Severity) model.Alert {
	return model.Alert{
		Type: model.AlertRiskyPort, Severity: sev, IP: ip, Port: p.Port,
		Message: strings.TrimSpace(fmt.Sprintf("%s 开放高危端口 %d/%s %s", ip, p.Port, p.Proto, p.Service)),
	}
}

func hostnameSuffix(h string) string {
	if h == "" {
		return ""
	}
	return " (" + h + ")"
}

// Vuln 为新发现或修复后复发的漏洞生成告警。
func Vuln(r model.CheckResult, reopened bool) model.Alert {
	prefix := "发现漏洞"
	if reopened {
		prefix = "漏洞复发"
	}
	return model.Alert{
		Type: model.AlertVuln, Severity: r.Severity, IP: r.IP, Port: r.Port,
		Message: fmt.Sprintf("%s %s:%d %s：%s", prefix, r.IP, r.Port, r.Title, r.Detail),
	}
}
