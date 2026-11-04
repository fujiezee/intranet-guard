package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"safe/internal/model"
	"safe/internal/pki"
	"safe/internal/store"
)

type nodeCtxKey struct{}

type nodeIdent struct {
	Kind   model.NodeKind
	ID     string
	Serial string
}

var validNodeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// NodeTLSConfig 返回节点接入端口的 TLS 配置：服务端证书由内部 CA 签发，
// 客户端证书可选（注册接口不需要），提供时必须由内部 CA 签发。
func NodeTLSConfig(ca *pki.CA, hosts []string, key *ecdsa.PrivateKey) (*tls.Config, error) {
	cert, err := ca.IssueServerCert(hosts, key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    ca.Pool(),
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func certIdent(r *http.Request) (nodeIdent, bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		return nodeIdent{}, false
	}
	c := r.TLS.VerifiedChains[0][0]
	if len(c.Subject.OrganizationalUnit) == 0 {
		return nodeIdent{}, false
	}
	return nodeIdent{Kind: model.NodeKind(c.Subject.OrganizationalUnit[0]), ID: c.Subject.CommonName, Serial: c.SerialNumber.Text(16)}, true
}

// requireNode 要求请求携带指定类型节点的有效证书，且节点未被吊销、证书是当前登记的那张。
func (s *Server) requireNode(kind model.NodeKind, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := certIdent(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "client certificate required")
			return
		}
		if id.Kind != kind {
			writeError(w, http.StatusForbidden, "certificate is not for a "+string(kind))
			return
		}
		active, err := s.store.ActiveNode(r.Context(), id.Kind, id.ID, id.Serial)
		if err != nil {
			writeInternal(w, err)
			return
		}
		if !active {
			writeError(w, http.StatusUnauthorized, "certificate revoked or superseded")
			return
		}
		if kind == model.NodeProbe {
			s.touchProbe(r.Context(), id.ID)
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), nodeCtxKey{}, id)))
	})
}

// probeTouchEvery 限制 last_seen 的写库频率：探针每 10 秒轮询一次任务，离线判定以分钟计，不需要每次都写。
const probeTouchEvery = 30 * time.Second

func (s *Server) touchProbe(ctx context.Context, id string) {
	now := time.Now()
	if last, ok := s.probeSeen.Load(id); ok && now.Sub(last.(time.Time)) < probeTouchEvery {
		return
	}
	if err := s.store.TouchProbe(ctx, id, now); err != nil {
		slog.Warn("touch probe", "probe", id, "err", err)
		return
	}
	s.probeSeen.Store(id, now)
}

// nodeIdentity 返回请求方的节点 ID。证书认证时以证书为准，请求里声明的 ID 必须为空或与证书一致；
// 旧版 token 认证无法验证身份，只能信任声明的 ID。
func nodeIdentity(w http.ResponseWriter, r *http.Request, claimed string) (string, bool) {
	if id, ok := r.Context().Value(nodeCtxKey{}).(nodeIdent); ok {
		if claimed != "" && claimed != id.ID {
			writeError(w, http.StatusForbidden, "node id does not match certificate")
			return "", false
		}
		return id.ID, true
	}
	if !validNodeID.MatchString(claimed) {
		writeError(w, http.StatusBadRequest, "invalid node id")
		return "", false
	}
	return claimed, true
}

func (s *Server) getCA(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(s.cfg.CA.CertPEM)
}

type enrollRequest struct {
	Token string         `json:"token"`
	Kind  model.NodeKind `json:"kind"`
	ID    string         `json:"id"`
	CSR   string         `json:"csr"`
}

type certResponse struct {
	Cert string `json:"cert"`
	CA   string `json:"ca"`
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var req enrollRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Kind != model.NodeProbe && req.Kind != model.NodeAgent {
		writeError(w, http.StatusBadRequest, "kind must be probe or agent")
		return
	}
	if !validNodeID.MatchString(req.ID) {
		writeError(w, http.StatusBadRequest, "id must be 1-128 characters of letters, digits, '.', '_' or '-'")
		return
	}
	secret, _, _ := strings.Cut(req.Token, ".")

	var certPEM []byte
	var signErr error
	_, err := s.store.Enroll(r.Context(), hashToken(secret), req.Kind, req.ID, func() (string, time.Time, error) {
		pemBytes, cert, err := s.cfg.CA.SignCSR([]byte(req.CSR), string(req.Kind), req.ID)
		if err != nil {
			signErr = err
			return "", time.Time{}, err
		}
		certPEM = pemBytes
		return cert.SerialNumber.Text(16), cert.NotAfter, nil
	})
	switch {
	case errors.Is(err, store.ErrTokenInvalid):
		slog.Warn("enrollment rejected: bad token", "kind", req.Kind, "id", req.ID, "remote", s.clientIP(r))
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	case errors.Is(err, store.ErrTokenKindDiffer):
		writeError(w, http.StatusForbidden, err.Error())
		return
	case errors.Is(err, store.ErrNodeEnrolled):
		writeError(w, http.StatusConflict, err.Error())
		return
	case signErr != nil:
		writeError(w, http.StatusBadRequest, "invalid CSR: "+signErr.Error())
		return
	case err != nil:
		writeInternal(w, err)
		return
	}
	slog.Info("node enrolled", "kind", req.Kind, "id", req.ID, "remote", s.clientIP(r))
	writeJSON(w, http.StatusOK, certResponse{Cert: string(certPEM), CA: string(s.cfg.CA.CertPEM)})
}

type renewRequest struct {
	CSR string `json:"csr"`
}

// renew 用当前有效证书换一张新证书。旧证书在续期后立即失效。
func (s *Server) renew(w http.ResponseWriter, r *http.Request) {
	id, ok := certIdent(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "client certificate required")
		return
	}
	if active, err := s.store.ActiveNode(r.Context(), id.Kind, id.ID, id.Serial); err != nil {
		writeInternal(w, err)
		return
	} else if !active {
		writeError(w, http.StatusUnauthorized, "certificate revoked or superseded")
		return
	}
	var req renewRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	certPEM, cert, err := s.cfg.CA.SignCSR([]byte(req.CSR), string(id.Kind), id.ID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CSR: "+err.Error())
		return
	}
	if err := s.store.RenewNode(r.Context(), id.Kind, id.ID, id.Serial, cert.SerialNumber.Text(16), cert.NotAfter); err != nil {
		writeInternal(w, err)
		return
	}
	slog.Info("node certificate renewed", "kind", id.Kind, "id", id.ID, "expires", cert.NotAfter)
	writeJSON(w, http.StatusOK, certResponse{Cert: string(certPEM), CA: string(s.cfg.CA.CertPEM)})
}

func (s *Server) listNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.store.ListNodes(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nodes)
}

func (s *Server) revokeNode(w http.ResponseWriter, r *http.Request) {
	kind, id := model.NodeKind(r.PathValue("kind")), r.PathValue("id")
	err := s.store.RevokeNode(r.Context(), kind, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "node not found")
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "node.revoke", string(kind)+"/"+id, "", true)
	w.WriteHeader(http.StatusNoContent)
}

type createEnrollTokenRequest struct {
	Kind     model.NodeKind `json:"kind"`
	MaxUses  int            `json:"max_uses"`
	TTLHours int            `json:"ttl_hours"`
	Note     string         `json:"note"`
}

type createEnrollTokenResponse struct {
	model.EnrollToken
	Token string `json:"token"` // 只返回这一次
}

func (s *Server) createEnrollToken(w http.ResponseWriter, r *http.Request) {
	var req createEnrollTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Kind != model.NodeProbe && req.Kind != model.NodeAgent {
		writeError(w, http.StatusBadRequest, "kind must be probe or agent")
		return
	}
	if req.MaxUses < 1 || req.MaxUses > 10000 {
		writeError(w, http.StatusBadRequest, "max_uses must be within 1-10000")
		return
	}
	if req.TTLHours < 1 || req.TTLHours > 24*30 {
		writeError(w, http.StatusBadRequest, "ttl_hours must be within 1-720")
		return
	}
	if len(req.Note) > 200 {
		writeError(w, http.StatusBadRequest, "note is too long")
		return
	}

	b := make([]byte, 16)
	_, _ = rand.Read(b)
	secret := hex.EncodeToString(b)
	t, err := s.store.CreateEnrollToken(r.Context(), model.EnrollToken{
		Kind: req.Kind, MaxUses: req.MaxUses, ExpiresAt: time.Now().Add(time.Duration(req.TTLHours) * time.Hour).UTC(),
		Note: req.Note, CreatedBy: userFrom(r.Context()).Username,
	}, hashToken(secret))
	if err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "enroll_token.create", strconv.FormatInt(t.ID, 10),
		fmt.Sprintf("kind=%s max_uses=%d ttl_hours=%d note=%s", t.Kind, t.MaxUses, req.TTLHours, t.Note), true)
	// 令牌 = 密钥.CA 指纹：节点据此在首次连接时校验管理中心身份。
	writeJSON(w, http.StatusCreated, createEnrollTokenResponse{EnrollToken: t, Token: secret + "." + s.cfg.CA.Fingerprint()})
}

func (s *Server) listEnrollTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := s.store.ListEnrollTokens(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tokens)
}

func (s *Server) deleteEnrollToken(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	switch err := s.store.DeleteEnrollToken(r.Context(), id); {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "token not found")
	case err != nil:
		writeInternal(w, err)
	default:
		s.audit(r, "", "enroll_token.delete", strconv.FormatInt(id, 10), "", true)
		w.WriteHeader(http.StatusNoContent)
	}
}
