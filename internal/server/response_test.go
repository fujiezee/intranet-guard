package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"safe/internal/model"
)

func TestResponseActions(t *testing.T) {
	ts, adminToken, st := newTestServerWithStore(t)
	info := model.AgentInfo{ID: "web01", Hostname: "web01", IPs: []string{"10.0.0.21"}}
	// report 上报一次并返回下发的指令；results 为上一轮的执行结果
	report := func(results ...model.CommandResult) []model.AgentCommand {
		t.Helper()
		var resp model.AgentReportResponse
		call(t, ts, agentToken, "POST", "/api/v1/agent/report", model.AgentReport{Agent: info, Events: []model.HostEvent{}, Results: results}, &resp)
		return resp.Commands
	}
	get := func(id string) model.ResponseAction {
		t.Helper()
		var list []model.ResponseAction
		call(t, ts, adminToken, "GET", "/api/v1/actions", nil, &list)
		for _, a := range list {
			if a.ID == id {
				return a
			}
		}
		t.Fatalf("action %s not found", id)
		return model.ResponseAction{}
	}

	// 校验
	for _, bad := range []createActionRequest{
		{AgentID: "web01", Type: model.ActBlockIP, Params: map[string]string{"ip": "127.0.0.1"}, Reason: "x"},
		{AgentID: "web01", Type: model.ActBlockIP, Params: map[string]string{"ip": "10.6.6.6", "duration": "10"}, Reason: "x"},
		{AgentID: "web01", Type: model.ActBlockIP, Params: map[string]string{"ip": "10.6.6.6"}},
		{AgentID: "web01", Type: model.ActKillProcess, Params: map[string]string{"pid": "1", "exe": "/sbin/init"}, Reason: "x"},
		{AgentID: "web01", Type: model.ActKillProcess, Params: map[string]string{"pid": "4242"}, Reason: "x"},
		{AgentID: "web01", Type: model.ActQuarantine, Params: map[string]string{"path": "/var/www/../etc/passwd"}, Reason: "x"},
		{AgentID: "web01", Type: model.ActUnblockIP, Params: map[string]string{"ip": "10.6.6.6"}, Reason: "x"},
		{AgentID: "web01", Type: "exec", Params: map[string]string{"cmd": "rm -rf /"}, Reason: "x"},
	} {
		if code := call(t, ts, adminToken, "POST", "/api/v1/actions", bad, nil); code != http.StatusBadRequest {
			t.Errorf("invalid action %+v accepted: %d", bad, code)
		}
	}

	// 封禁：创建 → Agent 领取（带有效期）→ 回报完成
	var block model.ResponseAction
	if code := call(t, ts, adminToken, "POST", "/api/v1/actions", createActionRequest{AgentID: "web01", Type: model.ActBlockIP,
		Params: map[string]string{"ip": "10.6.6.6"}, Reason: "SSH 爆破来源"}, &block); code != http.StatusCreated ||
		block.Status != model.ActPending || block.Params["duration"] != "86400" {
		t.Fatalf("create block: %d %+v", code, block)
	}
	cmds := report()
	if len(cmds) != 1 || cmds[0].Type != "action" || cmds[0].Action != model.ActBlockIP || cmds[0].ExpiresAt.Before(time.Now()) {
		t.Fatalf("commands: %+v", cmds)
	}
	if len(report()) != 0 {
		t.Error("action delivered twice")
	}
	report(model.CommandResult{ID: block.ID, Status: "done", Detail: "nftables 已封禁 10.6.6.6"})
	if a := get(block.ID); a.Status != model.ActDone || a.Result == "" {
		t.Fatalf("block after result: %+v", a)
	}

	// 撤销：生成解除动作，执行后原动作标记为已撤销；不能重复撤销
	var undo model.ResponseAction
	if code := call(t, ts, adminToken, "POST", "/api/v1/actions/"+block.ID+"/rollback", map[string]string{"reason": "误封"}, &undo); code != http.StatusCreated ||
		undo.Type != model.ActUnblockIP || undo.Params["ip"] != "10.6.6.6" || undo.RollbackOf != block.ID {
		t.Fatalf("rollback: %d %+v", code, undo)
	}
	if code := call(t, ts, adminToken, "POST", "/api/v1/actions/"+block.ID+"/rollback", nil, nil); code != http.StatusBadRequest {
		t.Errorf("double rollback: %d", code)
	}
	cmds = report()
	report(model.CommandResult{ID: cmds[0].ID, Status: "done"})
	if a := get(block.ID); a.Status != model.ActRolledBack {
		t.Errorf("original after undo: %+v", a)
	}

	// 隔离：需要另一位管理员批准，创建人不能自己批准
	var iso model.ResponseAction
	call(t, ts, adminToken, "POST", "/api/v1/actions", createActionRequest{AgentID: "web01", Type: model.ActIsolate,
		Params: map[string]string{"allow": "10.0.0.5"}, Reason: "反弹 shell"}, &iso)
	if iso.Status != model.ActAwaitingApproval {
		t.Fatalf("isolate status: %+v", iso)
	}
	if len(report()) != 0 {
		t.Error("unapproved isolation delivered")
	}
	if code := call(t, ts, adminToken, "POST", "/api/v1/actions/"+iso.ID+"/approve", nil, nil); code != http.StatusForbidden {
		t.Errorf("self approval: %d", code)
	}
	call(t, ts, adminToken, "POST", "/api/v1/users", createUserRequest{Username: "admin2", Password: "second-admin-pw", Role: model.RoleAdmin}, nil)
	admin2 := login(t, ts, "admin2", "second-admin-pw")
	if code := call(t, ts, admin2, "POST", "/api/v1/actions/"+iso.ID+"/approve", nil, nil); code != http.StatusNoContent {
		t.Fatalf("approve: %d", code)
	}
	if a := get(iso.ID); a.Status != model.ActPending || a.ApprovedBy != "admin2" {
		t.Errorf("approved isolate: %+v", a)
	}
	cmds = report()
	if len(cmds) != 1 || cmds[0].Action != model.ActIsolate || cmds[0].Params["allow"] != "10.0.0.5" {
		t.Fatalf("isolate command: %+v", cmds)
	}
	report(model.CommandResult{ID: iso.ID, Status: "error", Detail: "隔离主机需要 nftables"})
	if a := get(iso.ID); a.Status != model.ActFailed {
		t.Errorf("failed isolate: %+v", a)
	}
	if code := call(t, ts, adminToken, "POST", "/api/v1/actions/"+iso.ID+"/rollback", nil, nil); code != http.StatusBadRequest {
		t.Errorf("rollback of failed action: %d", code)
	}

	// 只读用户不能处置；Agent 不领取的动作 10 分钟后作废
	call(t, ts, adminToken, "POST", "/api/v1/users", createUserRequest{Username: "v", Password: "viewer-password", Role: model.RoleViewer}, nil)
	viewer := login(t, ts, "v", "viewer-password")
	if code := call(t, ts, viewer, "POST", "/api/v1/actions", createActionRequest{AgentID: "web01", Type: model.ActBlockIP,
		Params: map[string]string{"ip": "10.6.6.7"}, Reason: "x"}, nil); code != http.StatusForbidden {
		t.Errorf("viewer action: %d", code)
	}
	var stale model.ResponseAction
	call(t, ts, adminToken, "POST", "/api/v1/actions", createActionRequest{AgentID: "offline-host", Type: model.ActKillProcess,
		Params: map[string]string{"pid": "4242", "exe": "/tmp/x"}, Reason: "x"}, &stale)
	if n, err := st.ExpireActions(context.Background(), time.Now().Add(11*time.Minute)); err != nil || n != 1 {
		t.Fatalf("expire: %d %v", n, err)
	}
	if a := get(stale.ID); a.Status != model.ActExpired {
		t.Errorf("stale action: %+v", a)
	}

	var audit []model.AuditEntry
	call(t, ts, adminToken, "GET", "/api/v1/audit?action=action.approve", nil, &audit)
	if len(audit) != 1 || audit[0].Username != "admin2" {
		t.Errorf("approval audit: %+v", audit)
	}
}
