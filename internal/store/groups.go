package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"

	"safe/internal/alert"
	"safe/internal/model"
)

var ErrGroupExists = errors.New("group name already exists")

// ParseMembers 校验并规范化资产组成员（IP 或 CIDR）。
func ParseMembers(in []string) ([]string, error) {
	var out []string
	for _, m := range in {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		if p, err := netip.ParsePrefix(m); err == nil {
			out = append(out, p.Masked().String())
		} else if a, err := netip.ParseAddr(m); err == nil {
			out = append(out, a.Unmap().String())
		} else {
			return nil, errors.New("invalid member " + m + " (IP or CIDR expected)")
		}
	}
	return out, nil
}

// groupSet 是加载后的资产组，用于判断地址所属的组。
type groupSet []struct {
	model.AssetGroup
	prefixes []netip.Prefix
}

func (g groupSet) of(ip netip.Addr) []model.AssetGroup {
	var out []model.AssetGroup
	for _, x := range g {
		for _, p := range x.prefixes {
			if p.Contains(ip) {
				out = append(out, x.AssetGroup)
				break
			}
		}
	}
	return out
}

func (s *Store) loadGroups(ctx context.Context) (groupSet, error) {
	list, err := s.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	gs := make(groupSet, len(list))
	for i, g := range list {
		gs[i].AssetGroup = g
		for _, m := range g.Members {
			if p, err := netip.ParsePrefix(m); err == nil {
				gs[i].prefixes = append(gs[i].prefixes, p)
			} else if a, err := netip.ParseAddr(m); err == nil {
				gs[i].prefixes = append(gs[i].prefixes, netip.PrefixFrom(a, a.BitLen()))
			}
		}
	}
	return gs, nil
}

func (s *Store) ListGroups(ctx context.Context) ([]model.AssetGroup, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, kind, members, note, created_at FROM asset_groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AssetGroup{}
	for rows.Next() {
		var g model.AssetGroup
		var members string
		if err := rows.Scan(&g.ID, &g.Name, &g.Kind, &members, &g.Note, &g.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(members), &g.Members)
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) SaveGroup(ctx context.Context, g model.AssetGroup) (model.AssetGroup, error) {
	members, _ := json.Marshal(g.Members)
	var dup int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM asset_groups WHERE name = ? AND id <> ?`, g.Name, g.ID).Scan(&dup); err != nil {
		return g, err
	}
	if dup > 0 {
		return g, ErrGroupExists
	}
	if g.ID == 0 {
		g.CreatedAt = time.Now().UTC()
		err := s.db.QueryRowContext(ctx, `
			INSERT INTO asset_groups (name, kind, members, note, created_at) VALUES (?, ?, ?, ?, ?) RETURNING id`,
			g.Name, g.Kind, string(members), g.Note, g.CreatedAt).Scan(&g.ID)
		return g, err
	}
	return g, s.execOne(ctx, `UPDATE asset_groups SET name = ?, kind = ?, members = ?, note = ? WHERE id = ?`,
		g.Name, g.Kind, string(members), g.Note, g.ID)
}

func (s *Store) DeleteGroup(ctx context.Context, id int64) error {
	return s.execOne(ctx, `DELETE FROM asset_groups WHERE id = ?`, id)
}

// lateralTargets 返回某内网来源在横向移动窗口内登录过、且不属于正常运维范围的主机数：
// 来源属于运维跳板组时为 0；目标与来源同属一个集群组时不计入。
func (s *Store) lateralTargets(ctx context.Context, src netip.Addr, at time.Time) (int, error) {
	ids := s.logins.targets(src.String(), at)
	if len(ids) < alert.LateralTargets {
		return len(ids), nil
	}
	groups, err := s.loadGroups(ctx)
	if err != nil {
		return 0, err
	}
	srcClusters := map[int64]bool{}
	for _, g := range groups.of(src) {
		if g.Kind == model.GroupAdmin {
			return 0, nil
		}
		srcClusters[g.ID] = true
	}
	if len(srcClusters) == 0 {
		return len(ids), nil
	}
	agents, err := s.ListAgents(ctx)
	if err != nil {
		return 0, err
	}
	ipsOf := map[string][]string{}
	for _, a := range agents {
		ipsOf[a.ID] = a.IPs
	}
	n := 0
	for _, id := range ids {
		internal := false
		for _, ip := range ipsOf[id] {
			if a, err := netip.ParseAddr(ip); err == nil {
				for _, g := range groups.of(a) {
					if srcClusters[g.ID] {
						internal = true
					}
				}
			}
		}
		if !internal {
			n++
		}
	}
	return n, nil
}

// annotateGroups 填写资产所属的组名。
func (s *Store) annotateGroups(ctx context.Context, assets []model.Asset) error {
	groups, err := s.loadGroups(ctx)
	if err != nil || len(groups) == 0 {
		return err
	}
	for i := range assets {
		if a, err := netip.ParseAddr(assets[i].IP); err == nil {
			for _, g := range groups.of(a) {
				assets[i].Groups = append(assets[i].Groups, g.Name)
			}
		}
	}
	return nil
}
