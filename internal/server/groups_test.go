package server

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"safe/internal/model"
)

func TestAssetGroupsAndLateral(t *testing.T) {
	ts, adminToken := newTestServer(t)
	login := func(agent, ip, src string) {
		t.Helper()
		ev := model.HostEvent{Type: model.EventLoginSuccess, Time: time.Now(), User: "ops", SrcIP: src, Detail: "ssh publickey"}
		if code := call(t, ts, agentToken, "POST", "/api/v1/agent/report", model.AgentReport{
			Agent: model.AgentInfo{ID: agent, Hostname: agent, IPs: []string{ip}}, Events: []model.HostEvent{ev}}, nil); code != http.StatusOK {
			t.Fatalf("report: %d", code)
		}
	}
	lateralFrom := func(src string) bool {
		var alerts []model.Alert
		call(t, ts, adminToken, "GET", "/api/v1/alerts", nil, &alerts)
		for _, a := range alerts {
			if a.Type == model.AlertLateralMovement && a.IP == src {
				return true
			}
		}
		return false
	}

	// 校验
	for _, bad := range []model.AssetGroup{
		{Name: "", Kind: model.GroupCluster, Members: []string{"10.1.0.0/24"}},
		{Name: "x", Kind: "other", Members: []string{"10.1.0.0/24"}},
		{Name: "x", Kind: model.GroupCluster, Members: []string{"not-a-cidr"}},
		{Name: "x", Kind: model.GroupCluster},
	} {
		if code := call(t, ts, adminToken, "POST", "/api/v1/groups", bad, nil); code != http.StatusBadRequest {
			t.Errorf("invalid group %+v accepted: %d", bad, code)
		}
	}
	var hadoop, jump model.AssetGroup
	call(t, ts, adminToken, "POST", "/api/v1/groups", model.AssetGroup{Name: "Hadoop 集群", Kind: model.GroupCluster,
		Members: []string{"10.1.0.7/24", " 10.1.1.5 "}}, &hadoop)
	if hadoop.ID == 0 || hadoop.Members[0] != "10.1.0.0/24" || hadoop.Members[1] != "10.1.1.5" {
		t.Fatalf("hadoop group: %+v", hadoop)
	}
	call(t, ts, adminToken, "POST", "/api/v1/groups", model.AssetGroup{Name: "运维跳板", Kind: model.GroupAdmin, Members: []string{"10.9.0.10"}}, &jump)
	if code := call(t, ts, adminToken, "POST", "/api/v1/groups", model.AssetGroup{Name: "运维跳板", Kind: model.GroupAdmin,
		Members: []string{"10.9.0.11"}}, nil); code != http.StatusConflict {
		t.Errorf("duplicate name: %d", code)
	}

	// 1. 集群内部互访：10.1.0.1 登录 6 台集群节点 → 不告警
	for i := 2; i <= 7; i++ {
		login(fmt.Sprintf("hd%02d", i), fmt.Sprintf("10.1.0.%d", i), "10.1.0.1")
	}
	if lateralFrom("10.1.0.1") {
		t.Error("intra-cluster logins reported as lateral movement")
	}
	// 2. 同一集群节点登录集群外 5 台主机 → 仍告警（只豁免集群内部）
	for i := 1; i <= 5; i++ {
		login(fmt.Sprintf("web%02d", i), fmt.Sprintf("10.2.0.%d", i), "10.1.0.1")
	}
	if !lateralFrom("10.1.0.1") {
		t.Error("cluster node logging into 5 outside hosts not reported")
	}
	// 3. 运维跳板登录任意主机 → 不告警
	for i := 1; i <= 6; i++ {
		login(fmt.Sprintf("web%02d", i), fmt.Sprintf("10.2.0.%d", i), "10.9.0.10")
	}
	if lateralFrom("10.9.0.10") {
		t.Error("admin jump host reported as lateral movement")
	}
	// 4. 集群外来源登录 5 台集群节点 → 告警
	for i := 2; i <= 6; i++ {
		login(fmt.Sprintf("hd%02d", i), fmt.Sprintf("10.1.0.%d", i), "10.3.0.66")
	}
	if !lateralFrom("10.3.0.66") {
		t.Error("outside source into cluster not reported")
	}

	// 资产显示所属组；删除组后恢复
	runTask(t, ts, adminToken, false, []int{22}, asset("10.1.0.2", 22))
	var a model.Asset
	call(t, ts, adminToken, "GET", "/api/v1/assets/10.1.0.2", nil, &a)
	if len(a.Groups) != 1 || a.Groups[0] != "Hadoop 集群" {
		t.Errorf("asset groups: %+v", a.Groups)
	}
	if code := call(t, ts, adminToken, "DELETE", fmt.Sprintf("/api/v1/groups/%d", hadoop.ID), nil, nil); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	var after model.Asset
	call(t, ts, adminToken, "GET", "/api/v1/assets/10.1.0.2", nil, &after)
	if len(after.Groups) != 0 {
		t.Errorf("groups after delete: %+v", after.Groups)
	}
}
