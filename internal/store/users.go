package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"safe/internal/model"
)

var ErrConflict = errors.New("already exists")

// isUniqueViolation 识别 SQLite（UNIQUE constraint failed）和 PostgreSQL（SQLSTATE 23505）的唯一约束冲突。
func isUniqueViolation(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint") || strings.Contains(msg, "SQLSTATE 23505")
}

func (s *Store) CreateUser(ctx context.Context, username, passwordHash string, role model.Role) (model.User, error) {
	u := model.User{Username: username, Role: role, CreatedAt: time.Now().UTC()}
	err := s.db.QueryRowContext(ctx, `INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?) RETURNING id`,
		username, passwordHash, role, u.CreatedAt).Scan(&u.ID)
	if err != nil && isUniqueViolation(err) {
		return u, ErrConflict
	}
	return u, err
}

// GetUserByName 返回用户及其密码哈希，用于登录校验。
func (s *Store) GetUserByName(ctx context.Context, username string) (model.User, string, error) {
	var u model.User
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT id, username, role, created_at, password_hash FROM users WHERE username = ?`, username).
		Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return u, "", ErrNotFound
	}
	return u, hash, err
}

func (s *Store) ListUsers(ctx context.Context) ([]model.User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, username, role, created_at FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := []model.User{}
	for rows.Next() {
		var u model.User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

var ErrLastAdmin = errors.New("cannot remove the last admin")

// DeleteUser 删除用户及其会话，但不允许删除最后一个管理员。
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var role model.Role
	err = tx.QueryRowContext(ctx, `SELECT role FROM users WHERE id = ?`, id).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if role == model.RoleAdmin {
		var admins int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = ?`, model.RoleAdmin).Scan(&admins); err != nil {
			return err
		}
		if admins <= 1 {
			return ErrLastAdmin
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UpdatePassword(ctx context.Context, id int64, passwordHash string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, passwordHash, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	// 改密码后让该用户所有已登录会话失效。
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CreateSession(ctx context.Context, tokenHash string, userID int64, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)`,
		tokenHash, userID, expires.Unix())
	return err
}

// GetSessionUser 返回未过期会话对应的用户。
func (s *Store) GetSessionUser(ctx context.Context, tokenHash string) (model.User, error) {
	var u model.User
	err := s.db.QueryRowContext(ctx, `
		SELECT u.id, u.username, u.role, u.created_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND s.expires_at > ?`, tokenHash, time.Now().Unix()).
		Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

func (s *Store) DeleteExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, time.Now().Unix())
	return err
}

func (s *Store) CreateAPIToken(ctx context.Context, name, tokenHash, createdBy string) (model.APIToken, error) {
	t := model.APIToken{Name: name, CreatedBy: createdBy, CreatedAt: time.Now().UTC()}
	err := s.db.QueryRowContext(ctx, `INSERT INTO api_tokens (token_hash, name, created_by, created_at) VALUES (?, ?, ?, ?) RETURNING id`,
		tokenHash, name, createdBy, t.CreatedAt).Scan(&t.ID)
	return t, err
}

func (s *Store) ListAPITokens(ctx context.Context) ([]model.APIToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, created_by, created_at, last_used_at FROM api_tokens ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.APIToken{}
	for rows.Next() {
		var t model.APIToken
		var used sql.NullTime
		if err := rows.Scan(&t.ID, &t.Name, &t.CreatedBy, &t.CreatedAt, &used); err != nil {
			return nil, err
		}
		if used.Valid {
			t.LastUsedAt = &used.Time
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) DeleteAPIToken(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM api_tokens WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// UseAPIToken 返回令牌名称并记录使用时间（每分钟最多写一次，查询频繁时不产生大量写入）。
func (s *Store) UseAPIToken(ctx context.Context, tokenHash string) (string, error) {
	var name string
	var used sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT name, last_used_at FROM api_tokens WHERE token_hash = ?`, tokenHash).Scan(&name, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	} else if err != nil {
		return "", err
	}
	if now := time.Now().UTC(); !used.Valid || now.Sub(used.Time) > time.Minute {
		if _, err := s.db.ExecContext(ctx, `UPDATE api_tokens SET last_used_at = ? WHERE token_hash = ?`, now, tokenHash); err != nil {
			return "", err
		}
	}
	return name, nil
}
