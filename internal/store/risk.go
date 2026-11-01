package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"safe/internal/alert"
	"safe/internal/model"
)

// 风险评分：0-100，越高越应优先处理。各项分值是经验值，目的是排序而不是精确度量。
const (
	riskIncidentHigh   = 40
	riskIncidentMedium = 20
	riskVulnHigh       = 30
	riskVulnMedium     = 10
	riskPortHigh       = 10
	riskPortMedium     = 5
	riskAlertCap       = 30 // 近 7 天告警最多计入的分数
)

var importanceWeight = map[string]float64{model.ImportanceCore: 1.5, model.ImportanceImportant: 1.2}

type sevCount map[string]map[model.Severity]int // ip → 级别 → 数量

func (s *Store) countBySeverity(ctx context.Context, q string, args ...any) (sevCount, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := sevCount{}
	for rows.Next() {
		var ip string
		var sev model.Severity
		var n int
		if err := rows.Scan(&ip, &sev, &n); err != nil {
			return nil, err
		}
		if out[ip] == nil {
			out[ip] = map[model.Severity]int{}
		}
		out[ip][sev] = n
	}
	return out, rows.Err()
}

// scoreAssets 为资产计算风险分和原因。
func (s *Store) scoreAssets(ctx context.Context, assets []model.Asset) error {
	incidents, err := s.countBySeverity(ctx, `SELECT ip, severity, COUNT(*) FROM incidents WHERE status IN (?, ?) GROUP BY ip, severity`,
		model.IncidentOpen, model.IncidentInvestigating)
	if err != nil {
		return err
	}
	vulns, err := s.countBySeverity(ctx, `SELECT ip, severity, COUNT(*) FROM vulns WHERE status = ? GROUP BY ip, severity`, model.VulnOpen)
	if err != nil {
		return err
	}
	alerts, err := s.countBySeverity(ctx, `
		SELECT ip, severity, COUNT(*) FROM alerts
		WHERE status = ? AND created_at >= ? AND resolution NOT IN (?, ?) GROUP BY ip, severity`,
		model.AlertOpen, time.Now().Add(-7*24*time.Hour).UTC(), model.ResolutionSimulation, model.ResolutionFalsePositive)
	if err != nil {
		return err
	}

	for i := range assets {
		a := &assets[i]
		if a.Importance == "" {
			a.Importance = model.ImportanceNormal
		}
		score := 0
		var reasons []string
		add := func(n, points int, what string) {
			if n > 0 {
				score += n * points
				reasons = append(reasons, fmt.Sprintf("%s %d 个（+%d）", what, n, n*points))
			}
		}
		add(incidents[a.IP][model.SeverityHigh], riskIncidentHigh, "未结高危事件")
		add(incidents[a.IP][model.SeverityMedium], riskIncidentMedium, "未结中危事件")
		add(vulns[a.IP][model.SeverityHigh], riskVulnHigh, "高危漏洞")
		add(vulns[a.IP][model.SeverityMedium], riskVulnMedium, "中危漏洞")
		if !a.Honeypot {
			var high, medium []string
			for _, p := range a.Ports {
				if sev, ok := alert.RiskyPortSeverity(p.Port); ok {
					if sev == model.SeverityHigh {
						high = append(high, fmt.Sprint(p.Port))
					} else {
						medium = append(medium, fmt.Sprint(p.Port))
					}
				}
			}
			if len(high) > 0 {
				score += len(high) * riskPortHigh
				reasons = append(reasons, fmt.Sprintf("高危端口 %s（+%d）", strings.Join(high, "、"), len(high)*riskPortHigh))
			}
			if len(medium) > 0 {
				score += len(medium) * riskPortMedium
				reasons = append(reasons, fmt.Sprintf("敏感端口 %s（+%d）", strings.Join(medium, "、"), len(medium)*riskPortMedium))
			}
		}
		if n := alerts[a.IP][model.SeverityHigh]*5 + alerts[a.IP][model.SeverityMedium]*2; n > 0 {
			if n > riskAlertCap {
				n = riskAlertCap
			}
			score += n
			reasons = append(reasons, fmt.Sprintf("近 7 天未处理告警（+%d）", n))
		}
		if w, ok := importanceWeight[a.Importance]; ok && score > 0 {
			reasons = append(reasons, fmt.Sprintf("重要性加权 ×%.1f", w))
			score = int(float64(score) * w)
		}
		if score > 100 {
			score = 100
		}
		a.Risk, a.RiskReasons = score, reasons
	}
	return nil
}

// SetAssetMeta 设置资产的重要性、负责人和标签。
func (s *Store) SetAssetMeta(ctx context.Context, ip, importance, owner string, tags []string) error {
	return s.execOne(ctx, `UPDATE assets SET importance = ?, owner = ?, tags = ? WHERE ip = ?`,
		importance, owner, strings.Join(tags, ","), ip)
}
