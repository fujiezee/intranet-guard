package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"safe/internal/model"
	"safe/internal/store"
)

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListGroups(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// saveGroup 新建（POST）或修改（PUT /{id}）资产组。
func (s *Server) saveGroup(w http.ResponseWriter, r *http.Request) {
	var g model.AssetGroup
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&g); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	g.ID = 0
	if v := r.PathValue("id"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid id")
			return
		}
		g.ID = id
	}
	g.Name, g.Note = strings.TrimSpace(g.Name), strings.TrimSpace(g.Note)
	if g.Name == "" || len(g.Name) > 64 || len(g.Note) > 500 {
		writeError(w, http.StatusBadRequest, "name is required (at most 64 characters)")
		return
	}
	if g.Kind != model.GroupCluster && g.Kind != model.GroupAdmin {
		writeError(w, http.StatusBadRequest, "kind must be cluster or admin")
		return
	}
	members, err := store.ParseMembers(g.Members)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(members) == 0 || len(members) > 1000 {
		writeError(w, http.StatusBadRequest, "1-1000 members required")
		return
	}
	g.Members = members
	saved, err := s.store.SaveGroup(r.Context(), g)
	switch {
	case errors.Is(err, store.ErrGroupExists):
		writeError(w, http.StatusConflict, err.Error())
		return
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "group not found")
		return
	case err != nil:
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "group.save", strconv.FormatInt(saved.ID, 10),
		fmt.Sprintf("name=%s kind=%s members=%s", saved.Name, saved.Kind, strings.Join(saved.Members, ",")), true)
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.DeleteGroup(r.Context(), id); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "group not found")
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "group.delete", r.PathValue("id"), "", true)
	w.WriteHeader(http.StatusNoContent)
}
