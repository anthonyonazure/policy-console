package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/anthonyonazure/policy-console/internal/engine"
	"github.com/anthonyonazure/policy-console/internal/store"
	"github.com/anthonyonazure/policy-console/internal/wizard"
)

type buildoutReq struct {
	Answers wizard.Answers `json:"answers"`
}

// previewBuildplan shows the plan for a set of answers without saving it.
func (s *Server) previewBuildplan(w http.ResponseWriter, r *http.Request) {
	req, err := body[buildoutReq](r)
	if err != nil {
		fail(w, 400, errors.New("expected the answers"))
		return
	}
	a := req.Answers.Normalize()
	writeJSON(w, 200, map[string]any{"answers": a, "plan": wizard.Build(a, s.Cat.All())})
}

// createBuildout saves a plan for a client so its steps can be worked through.
func (s *Server) createBuildout(w http.ResponseWriter, r *http.Request) {
	tenant := r.PathValue("id")
	if !s.knownTenant(w, tenant) {
		return
	}
	req, err := body[buildoutReq](r)
	if err != nil {
		fail(w, 400, errors.New("expected the answers"))
		return
	}
	a := req.Answers.Normalize()
	plan := wizard.Build(a, s.Cat.All())
	var stepIDs []string
	for _, st := range plan.Steps {
		stepIDs = append(stepIDs, st.ID)
	}
	aj, _ := json.Marshal(a)
	pj, _ := json.Marshal(plan)
	id, err := s.Store.CreateBuildout(tenant, aj, pj, stepIDs, actor(r))
	if err != nil {
		fail(w, 500, err)
		return
	}
	// Seed the client's profile from the answers so tailoring matches what was said.
	if p, err := s.Store.GetProfile(tenant); err == nil {
		p.ThirdPartyEDR, p.RMMPatching, p.Regulated = a.ThirdPartyEDR, a.RMMPatching, a.Regulated
		p.BYOD = a.Ownership != "corporate"
		p.Platforms = a.Platforms
		_ = s.Store.SetProfile(tenant, p)
	}
	b, _ := s.Store.Buildout(id)
	writeJSON(w, 201, s.buildoutView(b))
}

func (s *Server) listBuildouts(w http.ResponseWriter, r *http.Request) {
	bs, err := s.Store.Buildouts(r.PathValue("id"))
	if err != nil {
		fail(w, 500, err)
		return
	}
	out := make([]any, 0, len(bs))
	for i := range bs {
		out = append(out, s.buildoutView(&bs[i]))
	}
	writeJSON(w, 200, out)
}

func (s *Server) getBuildout(w http.ResponseWriter, r *http.Request) {
	b, ok := s.loadBuildout(w, r)
	if !ok {
		return
	}
	writeJSON(w, 200, s.buildoutView(b))
}

func (s *Server) loadBuildout(w http.ResponseWriter, r *http.Request) (*store.Buildout, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, 400, errors.New("bad id"))
		return nil, false
	}
	b, err := s.Store.Buildout(id)
	if err != nil || b == nil {
		fail(w, 404, errors.New("no such build out"))
		return nil, false
	}
	return b, true
}

func planOf(b *store.Buildout) (wizard.Plan, error) {
	var p wizard.Plan
	return p, json.Unmarshal(b.Plan, &p)
}

// buildoutView adds to each step whether it can be started now and what blocks it.
func (s *Server) buildoutView(b *store.Buildout) map[string]any {
	plan, _ := planOf(b)
	type stepView struct {
		wizard.Step
		State    store.StepState `json:"progress"`
		Ready    bool            `json:"ready"`
		Blockers []string        `json:"blockedBy,omitempty"`
	}
	titles := map[string]string{}
	for _, st := range plan.Steps {
		titles[st.ID] = st.Title
	}
	var steps []stepView
	done := 0
	for _, st := range plan.Steps {
		sv := stepView{Step: st, State: b.Steps[st.ID]}
		sv.Ready = sv.State.State == "pending" || sv.State.State == "failed"
		for _, d := range st.DependsOn {
			if ds := b.Steps[d].State; ds != "done" && ds != "skipped" {
				sv.Ready = false
				sv.Blockers = append(sv.Blockers, titles[d])
			}
		}
		if sv.State.State == "done" || sv.State.State == "skipped" {
			done++
		}
		steps = append(steps, sv)
	}
	return map[string]any{"id": b.ID, "tenantId": b.TenantID, "answers": json.RawMessage(b.Answers), "createdBy": b.CreatedBy,
		"createdAt": b.CreatedAt, "steps": steps, "counts": plan.Counts, "notes": plan.Notes,
		"progress": map[string]int{"done": done, "total": len(plan.Steps)}}
}

func findStep(p wizard.Plan, id string) (wizard.Step, bool) {
	for _, st := range p.Steps {
		if st.ID == id {
			return st, true
		}
	}
	return wizard.Step{}, false
}

// stepReady refuses a step whose earlier steps are not finished.
func stepReady(b *store.Buildout, st wizard.Step, plan wizard.Plan) error {
	titles := map[string]string{}
	for _, s := range plan.Steps {
		titles[s.ID] = s.Title
	}
	var wait []string
	for _, d := range st.DependsOn {
		if ds := b.Steps[d].State; ds != "done" && ds != "skipped" {
			wait = append(wait, titles[d])
		}
	}
	if len(wait) > 0 {
		return fmt.Errorf("finish these first: %s", strings.Join(wait, "; "))
	}
	return nil
}

func (s *Server) deployInputs(b *store.Buildout, st wizard.Step) ([]string, map[string]string, string, error) {
	tokens, err := s.Store.Tokens(b.TenantID)
	if err != nil {
		return nil, nil, "", err
	}
	ids := append([]string(nil), st.TemplateIDs...)
	sort.Strings(ids)
	tj, _ := json.Marshal(tokens)
	h := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%s|%s", b.ID, st.ID, strings.Join(ids, ","), tj)))
	return ids, tokens, hex.EncodeToString(h[:]), nil
}

type stepReq struct {
	Hash    string `json:"hash"`
	Confirm bool   `json:"confirm"`
	Note    string `json:"note"`
	Reason  string `json:"reason"`
}

// stepPreview shows what running a deploy step would do. It creates nothing.
func (s *Server) stepPreview(w http.ResponseWriter, r *http.Request) {
	b, ok := s.loadBuildout(w, r)
	if !ok {
		return
	}
	plan, _ := planOf(b)
	st, ok := findStep(plan, r.PathValue("step"))
	if !ok || st.Type != wizard.TypeDeploy {
		fail(w, 400, errors.New("only a deploy step can be previewed"))
		return
	}
	ids, tokens, hash, err := s.deployInputs(b, st)
	if err != nil {
		fail(w, 500, err)
		return
	}
	res, err := s.Engine.Deploy(r.Context(), engine.DeployRequest{TenantID: b.TenantID, TemplateIDs: ids, Tokens: tokens, State: "enabledForReportingButNotEnforced",
		Preview: true, Actor: actor(r), Rollout: engine.RolloutNone})
	if err != nil {
		fail(w, 502, err)
		return
	}
	writeJSON(w, 200, map[string]any{"step": st.ID, "hash": hash, "items": res.Items, "unassigned": true})
}

// stepRun runs a deploy step for real, after a matching preview was confirmed.
// Everything is created unassigned and Conditional Access starts report-only.
func (s *Server) stepRun(w http.ResponseWriter, r *http.Request) {
	b, ok := s.loadBuildout(w, r)
	if !ok {
		return
	}
	plan, _ := planOf(b)
	st, ok := findStep(plan, r.PathValue("step"))
	if !ok || st.Type != wizard.TypeDeploy {
		fail(w, 400, errors.New("only a deploy step can be run"))
		return
	}
	q, _ := body[stepReq](r)
	if s.Cfg.ReadOnly {
		fail(w, 403, errors.New("the console is in read-only mode, so it will not create anything in a client"))
		return
	}
	if !q.Confirm || q.Hash == "" {
		fail(w, 400, errors.New("preview first, then confirm with the preview's hash"))
		return
	}
	if err := stepReady(b, st, plan); err != nil {
		fail(w, 409, err)
		return
	}
	ids, tokens, hash, err := s.deployInputs(b, st)
	if err != nil {
		fail(w, 500, err)
		return
	}
	if hash != q.Hash {
		fail(w, 409, errors.New("the plan or the client's values changed since the preview; preview again"))
		return
	}
	res, err := s.Engine.Deploy(r.Context(), engine.DeployRequest{TenantID: b.TenantID, TemplateIDs: ids, Tokens: tokens, State: "enabledForReportingButNotEnforced",
		Actor: actor(r), Rollout: engine.RolloutNone})
	if err != nil {
		_ = s.Store.SetStep(b.ID, st.ID, store.StepState{State: "failed", By: actor(r), Detail: err.Error()})
		s.afterStepChange(b.ID)
		fail(w, 502, err)
		return
	}
	failed, made := 0, 0
	for _, it := range res.Items {
		switch it.Result {
		case "failed":
			failed++
		case "created", "exists", "skipped":
			made++
		}
	}
	state := "done"
	detail := fmt.Sprintf("%d of %d policies in place", made, len(res.Items))
	if failed > 0 {
		state, detail = "failed", fmt.Sprintf("%d of %d policies failed", failed, len(res.Items))
	}
	_ = s.Store.SetStep(b.ID, st.ID, store.StepState{State: state, By: actor(r), RunID: res.RunID, Detail: detail})
	s.afterStepChange(b.ID)
	writeJSON(w, 200, map[string]any{"step": st.ID, "state": state, "detail": detail, "items": res.Items})
}

// stepComplete marks a manual, gate or check step as done by a named person.
func (s *Server) stepComplete(w http.ResponseWriter, r *http.Request) {
	b, ok := s.loadBuildout(w, r)
	if !ok {
		return
	}
	plan, _ := planOf(b)
	st, ok := findStep(plan, r.PathValue("step"))
	if !ok || st.Type == wizard.TypeDeploy {
		fail(w, 400, errors.New("a deploy step is finished by running it"))
		return
	}
	q, _ := body[stepReq](r)
	if st.Type == wizard.TypeGate && strings.TrimSpace(q.Note) == "" {
		fail(w, 400, errors.New("say what you checked: a gate needs a note"))
		return
	}
	if err := stepReady(b, st, plan); err != nil {
		fail(w, 409, err)
		return
	}
	if err := s.Store.SetStep(b.ID, st.ID, store.StepState{State: "done", By: actor(r), Note: strings.TrimSpace(q.Note)}); err != nil {
		fail(w, 500, err)
		return
	}
	s.afterStepChange(b.ID)
	writeJSON(w, 200, map[string]any{"step": st.ID, "state": "done"})
}

// stepSkip skips a step with a reason; later steps may then go ahead.
func (s *Server) stepSkip(w http.ResponseWriter, r *http.Request) {
	b, ok := s.loadBuildout(w, r)
	if !ok {
		return
	}
	plan, _ := planOf(b)
	st, ok := findStep(plan, r.PathValue("step"))
	if !ok {
		fail(w, 404, errors.New("no such step"))
		return
	}
	q, _ := body[stepReq](r)
	if strings.TrimSpace(q.Reason) == "" {
		fail(w, 400, errors.New("a skipped step needs a reason, so the handover report can say why"))
		return
	}
	if err := s.Store.SetStep(b.ID, st.ID, store.StepState{State: "skipped", By: actor(r), Note: strings.TrimSpace(q.Reason)}); err != nil {
		fail(w, 500, err)
		return
	}
	s.afterStepChange(b.ID)
	writeJSON(w, 200, map[string]any{"step": st.ID, "state": "skipped"})
}
