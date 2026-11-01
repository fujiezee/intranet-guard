package store

import (
	"sync"
	"time"

	"safe/internal/alert"
)

// 检测用的滑动窗口放在管理中心内存中，上报路径上不查询事件库：ClickHouse 擅长少量大批的分析查询，
// 1 万 Agent 压测中每秒数百次检测用的小查询（每次登录一次）使它占满 CPU。窗口都很短（最长 1 小时），代价是：
// 管理中心重启后窗口从空开始；多实例部署时各实例分别统计（正常情况下所有节点连接同一个实例）。

// loginWindow 记录最近 alert.LateralWindow 内各内网来源成功登录过的主机，用于横向移动检测。
//
// 放在内存中而不是每次查询事件库：ClickHouse 事件表的排序键以 agent_id 开头，"某来源登录过哪些主机"
// 需要扫描全表，1 万 Agent 压测中每秒数百次这样的查询使 ClickHouse 成为瓶颈。窗口只有 10 分钟，代价是：
// 管理中心重启后窗口从空开始；多实例部署时各实例分别统计（正常情况下所有节点连接同一个实例）。
type loginWindow struct {
	mu        sync.Mutex
	bySrc     map[string]map[string]time.Time // 来源 → 主机 → 最近一次登录时间
	lastPrune time.Time
}

func (w *loginWindow) add(src, agentID string, t time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.bySrc == nil {
		w.bySrc = map[string]map[string]time.Time{}
	}
	hosts := w.bySrc[src]
	if hosts == nil {
		hosts = map[string]time.Time{}
		w.bySrc[src] = hosts
	}
	if t.After(hosts[agentID]) {
		hosts[agentID] = t
	}
	if now := time.Now(); now.Sub(w.lastPrune) > time.Minute {
		w.prune(now)
	}
}

// targets 返回 src 在 [at - LateralWindow, at] 内登录过的主机。
func (w *loginWindow) targets(src string, at time.Time) []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	from := at.Add(-alert.LateralWindow)
	var out []string
	for id, t := range w.bySrc[src] {
		if !t.Before(from) && !t.After(at) {
			out = append(out, id)
		}
	}
	return out
}

func (w *loginWindow) prune(now time.Time) {
	w.lastPrune = now
	cutoff := now.Add(-2 * alert.LateralWindow) // 留出余量：上报可能延迟，事件时间早于收到时间
	for src, hosts := range w.bySrc {
		for id, t := range hosts {
			if t.Before(cutoff) {
				delete(hosts, id)
			}
		}
		if len(hosts) == 0 {
			delete(w.bySrc, src)
		}
	}
}

// maxFailuresPerKey：每个"主机 + 来源"最多保留的失败时间数。判定阈值远小于它，超出时丢弃最早的，内存有上界。
const maxFailuresPerKey = 1000

// failureWindow 记录各主机上各来源的登录失败时间（最近 alert.BruteForceLookback），用于暴力破解检测。
type failureWindow struct {
	mu        sync.Mutex
	byKey     map[string][]time.Time // 主机 + "|" + 来源 → 失败时间（按到达顺序）
	lastPrune time.Time
}

func (w *failureWindow) add(agentID, src string, t time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.byKey == nil {
		w.byKey = map[string][]time.Time{}
	}
	k := agentID + "|" + src
	ts := append(w.byKey[k], t)
	if len(ts) > maxFailuresPerKey {
		ts = ts[len(ts)-maxFailuresPerKey:]
	}
	w.byKey[k] = ts
	if now := time.Now(); now.Sub(w.lastPrune) > time.Minute {
		w.lastPrune = now
		cutoff := now.Add(-alert.BruteForceLookback - alert.LateralWindow) // 留出上报延迟的余量
		for k, ts := range w.byKey {
			kept := ts[:0]
			for _, t := range ts {
				if !t.Before(cutoff) {
					kept = append(kept, t)
				}
			}
			if len(kept) == 0 {
				delete(w.byKey, k)
			} else {
				w.byKey[k] = kept
			}
		}
	}
}

// count 返回 [from, to] 内的失败次数。
func (w *failureWindow) count(agentID, src string, from, to time.Time) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, t := range w.byKey[agentID+"|"+src] {
		if !t.Before(from) && !t.After(to) {
			n++
		}
	}
	return n
}
