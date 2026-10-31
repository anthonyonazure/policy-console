package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/anthonyonazure/policy-console/internal/planner"
	"github.com/anthonyonazure/policy-console/internal/report"
	"github.com/anthonyonazure/policy-console/internal/store"
	"github.com/anthonyonazure/policy-console/internal/wizard"
)

type reportReq struct {
	Baseline string `json:"baseline"` // empty is the House standard
}

// createReport assesses the client now and saves a dated, plain English report.
// It reads the tenant and changes nothing in it.
func (s *Server) createReport(w http.ResponseWriter, r *http.Request) {
	tenant := r.PathValue("id")
	t, err := s.Store.Tenant(tenant)
	if err != nil || t == nil {
		fail(w, 404, errors.New("unknown tenant"))
		return
	}
	q, _ := body[reportReq](r)
	if q.Baseline != "" && !s.knownBaseline(q.Baseline) {
		fail(w, 400, fmt.Errorf("unknown baseline %q", q.Baseline))
		return
	}
	tokens, _ := s.Store.Tokens(tenant)
	cmp, err := s.Engine.CompareAgainst(r.Context(), tenant, tokens, "", q.Baseline)
	if err != nil {
		fail(w, 502, fmt.Errorf("read the client's tenant: %w", err))
		return
	}
	label := "House standard"
	for _, c := range s.baselineChoices() {
		if c.ID == q.Baseline {
			label = c.Label
		}
	}
	d := report.Data{Client: t.Name, Generated: time.Now().Format("2 January 2006"), Baseline: label}
	for _, it := range cmp.Items {
		line := report.Line{Name: it.Template.Name}
		switch it.State {
		case "matches", "equivalent":
			d.Counts.InPlace++
			line.Detail = it.Does
			d.Protected = append(d.Protected, line)
		case "drifted":
			d.Counts.Differ++
			line.Detail = fmt.Sprintf("%d setting(s) differ from the standard", it.ChangeCount)
			d.Differing = append(d.Differing, line)
		case "missing":
			d.Counts.Missing++
			d.Missing = append(d.Missing, line)
		case "error":
			d.Counts.Unchecked++
		}
	}
	for _, e := range cmp.Excluded {
		d.Counts.Excluded++
		d.Excluded = append(d.Excluded, report.Line{Name: e.Name, Detail: e.Reason})
	}
	if open, err := s.Store.OpenFindings(tenant); err == nil {
		for _, f := range open {
			if f.StateAt(time.Now()) != store.StateNew {
				continue
			}
			if f.Severity == "critical" {
				d.Counts.Critical++
			} else if f.Severity == "warning" {
				d.Counts.Warning++
			}
			d.Findings = append(d.Findings, report.Line{Name: f.Name, Detail: f.Detail})
		}
	}
	if runs, err := s.Store.Runs(tenant, 40); err == nil {
		for _, run := range runs {
			switch run.Action {
			case "deploy", "modify", "revert", "rollout-assign", "rollout", "consent":
				if len(d.Changes) < 12 {
					d.Changes = append(d.Changes, report.Line{Name: run.Action + ", " + run.StartedAt, Detail: run.Summary})
				}
			}
		}
	}
	if ros, err := s.Store.Rollouts(tenant, true); err == nil {
		for _, ro := range ros {
			done := 0
			for _, ring := range ro.Rings {
				if ring.State == "activated" {
					done++
				}
			}
			d.Rollouts = append(d.Rollouts, report.Line{Name: ro.ObjectName, Detail: fmt.Sprintf("%d of %d stages started (%s)", done, len(ro.Rings), ro.State)})
		}
	}
	if prev, err := s.Store.Reports(tenant); err == nil {
		for _, p := range prev {
			if p.Baseline == q.Baseline {
				var c report.Counts
				if json.Unmarshal([]byte(p.Summary), &c) == nil {
					d.Previous = &c
				}
				break
			}
		}
	}
	d.NextSteps = report.NextSteps(d.Counts)
	sum, _ := json.Marshal(d.Counts)
	id, err := s.Store.SaveReport(store.SavedReport{TenantID: tenant, Baseline: q.Baseline, Summary: string(sum), HTML: report.HTML(d), CreatedBy: actor(r)})
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 201, map[string]any{"id": id, "counts": d.Counts, "percent": d.Counts.Percent(), "change": report.Delta(d.Counts, d.Previous)})
}

func (s *Server) listReports(w http.ResponseWriter, r *http.Request) {
	rs, err := s.Store.Reports(r.PathValue("id"))
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, rs)
}

// viewReport serves a saved report as a page. Its content is escaped when it is
// written, and the response also forbids scripts and outside resources.
func (s *Server) viewReport(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, 400, errors.New("bad id"))
		return
	}
	rep, err := s.Store.Report(id)
	if err != nil || rep == nil {
		fail(w, 404, errors.New("no such report"))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(rep.HTML))
}

// plannerSpec turns a build out plan into what Planner should show: one bucket
// per pack, one task per step, with where the step stands in its notes.
func (s *Server) plannerSpec(b *store.Buildout) planner.Spec {
	plan, _ := planOf(b)
	name := b.TenantID
	if t, _ := s.Store.Tenant(b.TenantID); t != nil && t.Name != "" {
		name = t.Name
	}
	shared := s.Cfg.PlannerPlanID != "" // many clients in one plan: say whose task it is
	titles := map[string]string{}
	for _, st := range plan.Steps {
		titles[st.ID] = st.Title
	}
	spec := planner.Spec{Title: "Intune build out: " + name}
	for _, st := range plan.Steps {
		desc := st.Why
		for _, n := range st.Notes {
			desc += "\n" + n
		}
		if st.Type == wizard.TypeManual {
			desc += "\nA person does this step; the console cannot yet."
		}
		var deps []string
		for _, d := range st.DependsOn {
			deps = append(deps, titles[d])
		}
		if len(deps) > 0 {
			desc += "\nDo these first: " + strings.Join(deps, ", ")
		}
		ps := b.Steps[st.ID]
		desc += "\n\nConsole status: " + ps.State
		if ps.By != "" {
			desc += " (by " + ps.By + ")"
		}
		if ps.Detail != "" {
			desc += ". " + ps.Detail
		}
		if ps.Note != "" {
			desc += ". Note: " + ps.Note
		}
		title, bucket := st.Title, st.Pack
		if shared {
			title, bucket = name+": "+st.Title, name+": "+st.Pack
		}
		spec.Tasks = append(spec.Tasks, planner.Task{StepID: st.ID, Title: title, Bucket: bucket, Description: desc, Done: ps.State == "done" || ps.State == "skipped"})
	}
	return spec
}

// plannerExport shows the plan as tasks without posting anything. It is the
// fallback for a console that is not connected to Planner.
func (s *Server) plannerExport(w http.ResponseWriter, r *http.Request) {
	b, ok := s.loadBuildout(w, r)
	if !ok {
		return
	}
	spec := s.plannerSpec(b)
	var buckets []string
	seen := map[string]bool{}
	for _, t := range spec.Tasks {
		if !seen[t.Bucket] {
			seen[t.Bucket] = true
			buckets = append(buckets, t.Bucket)
		}
	}
	type task struct {
		Title       string `json:"title"`
		Bucket      string `json:"bucket"`
		Description string `json:"description"`
		Done        bool   `json:"done"`
	}
	tasks := make([]task, 0, len(spec.Tasks))
	for _, t := range spec.Tasks {
		tasks = append(tasks, task{t.Title, t.Bucket, t.Description, t.Done})
	}
	writeJSON(w, 200, map[string]any{"planTitle": spec.Title, "buckets": buckets, "tasks": tasks})
}
