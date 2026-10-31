package api

import (
	"context"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/anthonyonazure/policy-console/internal/planner"
)

func (s *Server) syncer() (*planner.Syncer, error) {
	if s.Planner == nil || (s.Cfg.PlannerPlanID == "" && s.Cfg.PlannerGroupID == "") {
		return nil, planner.ErrNotConfigured
	}
	return &planner.Syncer{API: s.Planner, PlanID: s.Cfg.PlannerPlanID, GroupID: s.Cfg.PlannerGroupID}, nil
}

func (s *Server) plannerLock(id int64) *sync.Mutex {
	m, _ := s.plannerMu.LoadOrStore(id, &sync.Mutex{})
	return m.(*sync.Mutex)
}

// plannerStatus says whether the console is connected to Planner and how.
func (s *Server) plannerStatus(w http.ResponseWriter, r *http.Request) {
	_, err := s.syncer()
	mode := ""
	switch {
	case err != nil:
	case s.Cfg.PlannerPlanID != "":
		mode = "one shared plan"
	default:
		mode = "one plan per build out"
	}
	writeJSON(w, 200, map[string]any{"configured": err == nil, "mode": mode, "readOnly": s.Cfg.ReadOnly})
}

// plannerPreview says what posting would do, without calling Planner.
func (s *Server) plannerPreview(w http.ResponseWriter, r *http.Request) {
	b, ok := s.loadBuildout(w, r)
	if !ok {
		return
	}
	if _, err := s.syncer(); err != nil {
		fail(w, 503, err)
		return
	}
	writeJSON(w, 200, planner.Plan(s.plannerSpec(b), s.Store.PlannerState(b.ID)))
}

// plannerSync posts the plan to Planner, or brings a plan posted earlier up to
// date. It creates and edits only; it never deletes anything in Planner.
func (s *Server) plannerSync(w http.ResponseWriter, r *http.Request) {
	b, ok := s.loadBuildout(w, r)
	if !ok {
		return
	}
	if s.Cfg.ReadOnly {
		fail(w, 403, errors.New("the console is in read-only mode, so it will not write to Planner"))
		return
	}
	sy, err := s.syncer()
	if err != nil {
		fail(w, 503, err)
		return
	}
	mu := s.plannerLock(b.ID)
	mu.Lock()
	defer mu.Unlock()
	res, err := sy.Sync(r.Context(), s.plannerSpec(b), s.Store.PlannerState(b.ID))
	if err != nil {
		fail(w, 502, err)
		return
	}
	writeJSON(w, 200, res)
}

// afterStepChange keeps Planner current when a step moves, but only for a build
// out that was posted on purpose. It never posts one for the first time.
func (s *Server) afterStepChange(buildoutID int64) {
	sy, err := s.syncer()
	if err != nil || s.Cfg.ReadOnly || s.Store.PlannerState(buildoutID).Plan() == "" {
		return
	}
	run := func() {
		mu := s.plannerLock(buildoutID)
		mu.Lock()
		defer mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		b, err := s.Store.Buildout(buildoutID)
		if err != nil || b == nil {
			return
		}
		if _, err := sy.Sync(ctx, s.plannerSpec(b), s.Store.PlannerState(buildoutID)); err != nil {
			log.Printf("planner: update for build out %d failed, the next change or a manual sync will retry: %v", buildoutID, err)
		}
	}
	if s.PlannerAsync {
		go run()
		return
	}
	run()
}
