package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"safe/internal/model"
)

var (
	ErrTokenInvalid    = errors.New("enrollment token is invalid, expired or used up")
	ErrNodeEnrolled    = errors.New("node is already enrolled; revoke it first")
	ErrTokenKindDiffer = errors.New("enrollment token is for a different node kind")
)

func (s *Store) CreateEnrollToken(ctx context.Context, t model.EnrollToken, tokenHash string) (model.EnrollToken, error) {
	t.CreatedAt = time.Now().UTC()
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO enroll_tokens (token_hash, kind, max_uses, uses, expires_at, note, created_by, created_at)
		VALUES (?, ?, ?, 0, ?, ?, ?, ?) RETURNING id`,
		tokenHash, t.Kind, t.MaxUses, t.ExpiresAt.Unix(), t.Note, t.CreatedBy, t.CreatedAt).Scan(&t.ID)
	return t, err
}

func (s *Store) ListEnrollTokens(ctx context.Context) ([]model.EnrollToken, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, kind, max_uses, uses, expires_at, note, created_by, created_at FROM enroll_tokens ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.EnrollToken{}
	for rows.Next() {
		var t model.EnrollToken
		var exp int64
		if err := rows.Scan(&t.ID, &t.Kind, &t.MaxUses, &t.Uses, &exp, &t.Note, &t.CreatedBy, &t.CreatedAt); err != nil {
			return nil, err
		}
		t.ExpiresAt = time.Unix(exp, 0).UTC()
		out = append(out, t)
	}
	return out, rows.Err()
}

// EnrollTokenKind 查询令牌的节点类型，不占用额度。usable 表示仍可用于注册（未过期、未用完）；
// 令牌不存在时返回 ErrNotFound。
func (s *Store) EnrollTokenKind(ctx context.Context, tokenHash string) (kind model.NodeKind, usable bool, err error) {
	var uses, maxUses int
	var exp int64
	err = s.db.QueryRowContext(ctx, `SELECT kind, uses, max_uses, expires_at FROM enroll_tokens WHERE token_hash = ?`,
		tokenHash).Scan(&kind, &uses, &maxUses, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, ErrNotFound
	} else if err != nil {
		return "", false, err
	}
	return kind, uses < maxUses && exp > time.Now().Unix(), nil
}

func (s *Store) DeleteEnrollToken(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM enroll_tokens WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Enroll 在一个事务里校验令牌、检查节点 ID 未被占用、签发证书并登记节点。
// sign 由调用方提供（签发证书），只有校验全部通过后才会被调用。
func (s *Store) Enroll(ctx context.Context, tokenHash string, kind model.NodeKind, id string,
	sign func() (serial string, expiry time.Time, err error)) (model.Node, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.Node{}, err
	}
	defer tx.Rollback()

	// 先原子地占用一次令牌额度：并发注册时不会超出 max_uses。失败的注册随事务回滚归还额度。
	var tokenID int64
	var tokenKind model.NodeKind
	err = tx.QueryRowContext(ctx, `
		UPDATE enroll_tokens SET uses = uses + 1
		WHERE token_hash = ? AND uses < max_uses AND expires_at > ? RETURNING id, kind`,
		tokenHash, time.Now().Unix()).Scan(&tokenID, &tokenKind)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Node{}, ErrTokenInvalid
	} else if err != nil {
		return model.Node{}, err
	}
	if tokenKind != kind {
		return model.Node{}, ErrTokenKindDiffer
	}

	var status model.NodeStatus
	err = tx.QueryRowContext(ctx, `SELECT status FROM nodes WHERE kind = ? AND id = ?`, kind, id).Scan(&status)
	if err == nil && status == model.NodeActive {
		return model.Node{}, ErrNodeEnrolled
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return model.Node{}, err
	}

	serial, expiry, err := sign()
	if err != nil {
		return model.Node{}, err
	}
	n := model.Node{Kind: kind, ID: id, Serial: serial, Status: model.NodeActive, CertExpiry: expiry.UTC(),
		EnrolledAt: time.Now().UTC(), TokenID: tokenID}
	// 只覆盖已吊销的同名节点；并发注册同一 ID 时只有一个成功。
	res, err := tx.ExecContext(ctx, `
		INSERT INTO nodes (kind, id, serial, status, cert_expiry, enrolled_at, token_id) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(kind, id) DO UPDATE SET serial = excluded.serial, status = excluded.status,
			cert_expiry = excluded.cert_expiry, enrolled_at = excluded.enrolled_at, token_id = excluded.token_id
		WHERE nodes.status <> ?`,
		n.Kind, n.ID, n.Serial, n.Status, n.CertExpiry.Unix(), n.EnrolledAt, n.TokenID, model.NodeActive)
	if err != nil {
		return model.Node{}, err
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return model.Node{}, ErrNodeEnrolled
	}
	return n, tx.Commit()
}

// ActiveNode 返回证书序列号与当前登记一致且未吊销的节点；旧证书（续期前的）和吊销节点都会被拒绝。
func (s *Store) ActiveNode(ctx context.Context, kind model.NodeKind, id, serial string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM nodes WHERE kind = ? AND id = ? AND serial = ? AND status = ?`,
		kind, id, serial, model.NodeActive).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// RenewNode 把节点登记的证书换成新签发的证书。
func (s *Store) RenewNode(ctx context.Context, kind model.NodeKind, id, oldSerial, newSerial string, expiry time.Time) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE nodes SET serial = ?, cert_expiry = ? WHERE kind = ? AND id = ? AND serial = ? AND status = ?`,
		newSerial, expiry.Unix(), kind, id, oldSerial, model.NodeActive)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) RevokeNode(ctx context.Context, kind model.NodeKind, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE nodes SET status = ? WHERE kind = ? AND id = ?`, model.NodeRevoked, kind, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListNodes(ctx context.Context) ([]model.Node, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT kind, id, serial, status, cert_expiry, enrolled_at, token_id FROM nodes ORDER BY kind, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Node{}
	for rows.Next() {
		var n model.Node
		var exp int64
		if err := rows.Scan(&n.Kind, &n.ID, &n.Serial, &n.Status, &exp, &n.EnrolledAt, &n.TokenID); err != nil {
			return nil, err
		}
		n.CertExpiry = time.Unix(exp, 0).UTC()
		out = append(out, n)
	}
	return out, rows.Err()
}
