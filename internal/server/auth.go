package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"safe/internal/model"
	"safe/internal/store"
)

const (
	sessionTTL        = 12 * time.Hour
	minPasswordLength = 10
	loginMaxFailures  = 5
	loginLockout      = 5 * time.Minute
)

type ctxKey struct{}

func userFrom(ctx context.Context) model.User {
	u, _ := ctx.Value(ctxKey{}).(model.User)
	return u
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func bearer(r *http.Request) string {
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return tok
}

// requireRole 校验会话，并要求用户拥有指定角色；viewer 表示任何已登录用户。
func (s *Server) requireRole(role model.Role, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if tok == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		u, err := s.store.GetSessionUser(r.Context(), hashToken(tok))
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		} else if err != nil {
			writeInternal(w, err)
			return
		}
		if role == model.RoleAdmin && u.Role != model.RoleAdmin {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u)))
	})
}

// loginLimiter 按客户端 IP 限制登录失败次数，缓解在线爆破。
type loginLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

func (l *loginLimiter) blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := time.Now().Add(-loginLockout)
	recent := l.failures[ip][:0]
	for _, t := range l.failures[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	if len(recent) == 0 {
		delete(l.failures, ip)
		return false
	}
	l.failures[ip] = recent
	return len(recent) >= loginMaxFailures
}

func (l *loginLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failures[ip] = append(l.failures[ip], time.Now())
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, ip)
}

// clientIP 返回请求方的真实 IP。只有直连方是受信任的反向代理时才采用 X-Forwarded-For，
// 并从右往左取第一个非代理地址（最右侧是离我们最近的代理追加的，左侧部分可能被客户端伪造）。
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || !s.trustedProxy(peer) {
		return host
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			return host
		}
		if !s.trustedProxy(a) {
			return a.String()
		}
	}
	return host
}

func (s *Server) trustedProxy(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range s.cfg.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// dummyHash 用于用户不存在时也执行一次 bcrypt，避免通过响应时间枚举用户名。
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-password"), bcrypt.DefaultCost)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token     string     `json:"token"`
	ExpiresAt time.Time  `json:"expires_at"`
	User      model.User `json:"user"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if s.limiter.blocked(ip) {
		s.audit(r, "-", "auth.login", "", "blocked: too many failed attempts", false)
		writeError(w, http.StatusTooManyRequests, "too many failed attempts, try again later")
		return
	}
	var req loginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	u, hash, err := s.store.GetUserByName(r.Context(), req.Username)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		writeInternal(w, err)
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(req.Password))
	}
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		s.limiter.fail(ip)
		s.audit(r, req.Username, "auth.login", "", "invalid username or password", false)
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	s.limiter.reset(ip)

	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)
	expires := time.Now().Add(sessionTTL)
	if err := s.store.CreateSession(r.Context(), hashToken(token), u.ID, expires); err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, u.Username, "auth.login", "", "", true)
	writeJSON(w, http.StatusOK, loginResponse{Token: token, ExpiresAt: expires.UTC(), User: u})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteSession(r.Context(), hashToken(bearer(r))); err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "auth.logout", "", "", true)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, userFrom(r.Context()))
}

type changePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	var req changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	u := userFrom(r.Context())
	_, hash, err := s.store.GetUserByName(r.Context(), u.Username)
	if err != nil {
		writeInternal(w, err)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.OldPassword)) != nil {
		s.audit(r, "", "user.password", u.Username, "old password incorrect", false)
		writeError(w, http.StatusBadRequest, "old password is incorrect")
		return
	}
	newHash, err := HashPassword(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.UpdatePassword(r.Context(), u.ID, newHash); err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "user.password", u.Username, "", true)
	w.WriteHeader(http.StatusNoContent)
}

// HashPassword 校验密码强度并生成 bcrypt 哈希。
func HashPassword(pw string) (string, error) {
	if len(pw) < minPasswordLength {
		return "", errors.New("password must be at least " + strconv.Itoa(minPasswordLength) + " characters")
	}
	if len(pw) > 72 {
		return "", errors.New("password must be at most 72 bytes")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(h), err
}

type createUserRequest struct {
	Username string     `json:"username"`
	Password string     `json:"password"`
	Role     model.Role `json:"role"`
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || len(req.Username) > 64 {
		writeError(w, http.StatusBadRequest, "username must be 1-64 characters")
		return
	}
	if req.Role != model.RoleAdmin && req.Role != model.RoleViewer {
		writeError(w, http.StatusBadRequest, "role must be admin or viewer")
		return
	}
	hash, err := HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	u, err := s.store.CreateUser(r.Context(), req.Username, hash, req.Role)
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "username already exists")
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "user.create", u.Username, "role="+string(u.Role), true)
	writeJSON(w, http.StatusCreated, u)
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	if id == userFrom(r.Context()).ID {
		writeError(w, http.StatusBadRequest, "cannot delete yourself")
		return
	}
	switch err := s.store.DeleteUser(r.Context(), id); {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "user not found")
	case errors.Is(err, store.ErrLastAdmin):
		writeError(w, http.StatusBadRequest, err.Error())
	case err != nil:
		writeInternal(w, err)
	default:
		s.audit(r, "", "user.delete", strconv.FormatInt(id, 10), "", true)
		w.WriteHeader(http.StatusNoContent)
	}
}
