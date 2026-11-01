package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"safe/internal/model"
	"safe/internal/store"
)

func (s *Server) submitIDSEvents(w http.ResponseWriter, r *http.Request) {
	var rep model.IDSReport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<20)).Decode(&rep); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	var ok bool
	if rep.ProbeID, ok = nodeIdentity(w, r, rep.ProbeID); !ok {
		return
	}
	err := s.store.SaveIDSReport(r.Context(), rep)
	if errors.Is(err, store.ErrTooManyEvents) {
		writeError(w, http.StatusRequestEntityTooLarge, err.Error())
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	slog.Info("IDS events saved", "probe", rep.ProbeID, "events", len(rep.Events))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listIDSEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.IDSFilter{ProbeID: q.Get("probe_id"), SrcIP: q.Get("src_ip"), DestIP: q.Get("dest_ip"), Limit: 500}
	for name, dst := range map[string]*int{"max_severity": &f.MaxSeverity, "limit": &f.Limit} {
		if v := q.Get(name); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > 5000 {
				writeError(w, http.StatusBadRequest, name+" must be within 0-5000")
				return
			}
			*dst = n
		}
	}
	if v := q.Get("signature_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid signature_id")
			return
		}
		f.SignatureID = n
	}
	if f.Limit == 0 {
		f.Limit = 500
	}
	events, err := s.store.ListIDSEvents(r.Context(), f)
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) listSuppressions(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.ListSuppressions(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createSuppression(w http.ResponseWriter, r *http.Request) {
	var sp model.IDSSuppression
	if err := json.NewDecoder(r.Body).Decode(&sp); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if sp.SignatureID <= 0 {
		writeError(w, http.StatusBadRequest, "signature_id is required")
		return
	}
	sp.SrcIP = strings.TrimSpace(sp.SrcIP)
	if sp.SrcIP != "" {
		if _, err := netip.ParseAddr(sp.SrcIP); err != nil {
			writeError(w, http.StatusBadRequest, "invalid src_ip")
			return
		}
	}
	if len(sp.Note) > 500 {
		writeError(w, http.StatusBadRequest, "note is too long")
		return
	}
	sp.CreatedBy = userFrom(r.Context()).Username
	sp, err := s.store.CreateSuppression(r.Context(), sp)
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "suppression already exists")
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "ids.suppression.create", strconv.FormatInt(sp.SignatureID, 10), "src="+sp.SrcIP+" note="+sp.Note, true)
	writeJSON(w, http.StatusCreated, sp)
}

func (s *Server) deleteSuppression(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	switch err := s.store.DeleteSuppression(r.Context(), id); {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "suppression not found")
	case err != nil:
		writeInternal(w, err)
	default:
		s.audit(r, "", "ids.suppression.delete", strconv.FormatInt(id, 10), "", true)
		w.WriteHeader(http.StatusNoContent)
	}
}
