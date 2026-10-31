package api

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/engine"
	"github.com/anthonyonazure/policy-console/internal/store"
)

func (s *Server) knownTenant(w http.ResponseWriter, id string) bool {
	if t, err := s.Store.Tenant(id); err != nil || t == nil {
		fail(w, 404, errors.New("unknown tenant"))
		return false
	}
	return true
}

func (s *Server) getProfile(w http.ResponseWriter, r *http.Request) {
	p, err := s.Store.GetProfile(r.PathValue("id"))
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, p)
}

func (s *Server) putProfile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.knownTenant(w, id) {
		return
	}
	p, err := body[store.Profile](r)
	if err != nil {
		fail(w, 400, errors.New("expected the client profile"))
		return
	}
	if err := s.Store.SetProfile(id, p); err != nil {
		fail(w, 400, err)
		return
	}
	got, _ := s.Store.GetProfile(id)
	writeJSON(w, 200, got)
}

type overlayReq struct {
	TemplateID string `json:"templateId"`
	Op         string `json:"op"`
	Patch      string `json:"patch"` // JSON merge patch text, for modify
	Reason     string `json:"reason"`
	Owner      string `json:"owner"`
	ExpiresAt  string `json:"expiresAt"`
}

func (s *Server) addOverlay(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.knownTenant(w, id) {
		return
	}
	q, err := body[overlayReq](r)
	if err != nil {
		fail(w, 400, errors.New("expected an overlay"))
		return
	}
	tpl := s.Cat.Get(q.TemplateID)
	if tpl == nil {
		fail(w, 404, fmt.Errorf("unknown template %q", q.TemplateID))
		return
	}
	if q.Owner = strings.TrimSpace(q.Owner); q.Owner == "" {
		q.Owner = actor(r)
	}
	if q.Op == "modify" {
		// The patch must produce a policy that still reads as JSON.
		if _, err := engine.MergePatch(tpl.Body, []byte(q.Patch)); err != nil {
			fail(w, 400, fmt.Errorf("the patch cannot be applied to this template: %w", err))
			return
		}
	}
	exp, err := parseExpiry(q.ExpiresAt, nowFn())
	if err != nil {
		fail(w, 400, err)
		return
	}
	oid, err := s.Store.SetOverlay(store.Overlay{TenantID: id, TemplateID: q.TemplateID, Op: q.Op, Patch: q.Patch, Reason: q.Reason, Owner: q.Owner, ExpiresAt: exp})
	if err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, 201, map[string]any{"id": oid})
}

func (s *Server) listOverlays(w http.ResponseWriter, r *http.Request) {
	os, err := s.Store.Overlays(r.PathValue("id"))
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, os)
}

func (s *Server) deleteOverlay(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, 400, errors.New("bad id"))
		return
	}
	if err := s.Store.DeleteOverlay(id); err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}

type tailoringRow struct {
	TemplateID string `json:"templateId"`
	Name       string `json:"name"`
	Category   string `json:"category"`
	State      string `json:"state"` // included | modified | excluded
	Reason     string `json:"reason,omitempty"`
	Owner      string `json:"owner,omitempty"`
}

// tailoring is the Included, Modified, Excluded table for one client: for every
// template in the standard, whether the client gets it as it is, with changes,
// or not at all, and why.
func (s *Server) tailoring(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.knownTenant(w, id) {
		return
	}
	tl, err := s.Engine.LoadTailoring(id)
	if err != nil {
		fail(w, 500, err)
		return
	}
	var rows []tailoringRow
	counts := map[string]int{}
	for _, t := range s.Cat.All() {
		if catalog.IsLibrary(t.Category) || t.Category == "microsoft" || t.Category == "praxis" {
			continue
		}
		_, st := tl.Apply(t)
		rows = append(rows, tailoringRow{TemplateID: t.ID, Name: t.Name, Category: t.Category, State: st.State, Reason: st.Reason, Owner: st.Owner})
		counts[st.State]++
	}
	sort.SliceStable(rows, func(i, j int) bool {
		rank := map[string]int{"excluded": 0, "modified": 1, "included": 2}
		return rank[rows[i].State] < rank[rows[j].State]
	})
	writeJSON(w, 200, map[string]any{"profile": tl.Profile, "counts": counts, "rows": rows})
}
