package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/impact"
)

type impactReq struct {
	TemplateID string `json:"templateId"`
	// Overrides is the what-if: a value turns a setting on at that value, null or
	// false turns it off. Nothing is written to the client.
	Overrides map[string]any `json:"overrides"`
}

// impactPreview says which of a client's devices would comply with a compliance
// policy, which would fail and why, before anything is deployed. It reads
// devices and changes nothing, so a viewer may use it.
func (s *Server) impactPreview(w http.ResponseWriter, r *http.Request) {
	if s.Impact == nil {
		fail(w, 503, errors.New("the impact preview is not configured"))
		return
	}
	req, err := body[impactReq](r)
	if err != nil || req.TemplateID == "" {
		fail(w, 400, errors.New(`expected {"templateId": "...", "overrides": {...}}`))
		return
	}
	t := s.Cat.Get(req.TemplateID)
	if t == nil {
		fail(w, 404, fmt.Errorf("unknown template %q", req.TemplateID))
		return
	}
	if t.Kind != catalog.KindCompliance {
		fail(w, 400, errors.New("the impact preview supports compliance policies so far"))
		return
	}
	cfg, platform, notPredictable, err := impact.ConfigFromPolicy(t.Body)
	if err != nil {
		fail(w, 400, err)
		return
	}
	if tn, err := s.Store.Tenant(r.PathValue("id")); err != nil || tn == nil {
		fail(w, 404, errors.New("unknown tenant"))
		return
	}
	devices, err := s.Impact.Devices(r.Context(), r.PathValue("id"))
	if err != nil {
		fail(w, 502, fmt.Errorf("read the client's devices: %w", err))
		return
	}
	res := impact.Evaluate(platform, cfg.Apply(req.Overrides), notPredictable, devices, time.Now().UTC())
	sample := false
	if sm, ok := s.Impact.(interface{ IsSample() bool }); ok {
		sample = sm.IsSample()
	}
	writeJSON(w, 200, map[string]any{
		"template": map[string]string{"id": t.ID, "name": t.Name},
		"result":   res,
		"sample":   sample, // true means the devices are invented demo data
	})
}

type observedReq struct {
	PolicyID   string         `json:"policyId"`   // the live policy in the client
	TemplateID string         `json:"templateId"` // optional: set the prediction beside the result
	Overrides  map[string]any `json:"overrides"`
}

// impactObserved reports what Intune itself says about a deployed policy, device
// by device, and, when a template is given, sets the preview's prediction beside
// it. It reads and changes nothing.
func (s *Server) impactObserved(w http.ResponseWriter, r *http.Request) {
	tenant := r.PathValue("id")
	q, err := body[observedReq](r)
	if err != nil || q.PolicyID == "" {
		fail(w, 400, errors.New(`expected {"policyId": "...", "templateId": "..."}`))
		return
	}
	if t, err := s.Store.Tenant(tenant); err != nil || t == nil {
		fail(w, 404, errors.New("unknown tenant"))
		return
	}
	obs, err := impact.ObservedFromGraph(r.Context(), s.Engine.Reader(tenant), q.PolicyID)
	if err != nil {
		fail(w, 502, fmt.Errorf("read the policy's device results: %w", err))
		return
	}
	pct, have := obs.PercentCompliant()
	out := map[string]any{"observed": obs, "percentCompliant": pct, "anyReported": have}
	if q.TemplateID != "" && s.Impact != nil {
		t := s.Cat.Get(q.TemplateID)
		if t == nil || t.Kind != catalog.KindCompliance {
			fail(w, 400, errors.New("templateId must be a compliance template"))
			return
		}
		cfg, platform, np, err := impact.ConfigFromPolicy(t.Body)
		if err != nil {
			fail(w, 400, err)
			return
		}
		devices, err := s.Impact.Devices(r.Context(), tenant)
		if err != nil {
			fail(w, 502, fmt.Errorf("read the client's devices: %w", err))
			return
		}
		pred := impact.Evaluate(platform, cfg.Apply(q.Overrides), np, devices, time.Now().UTC())
		out["predicted"] = pred.Counts
		out["comparison"] = impact.Compare(pred.Devices, obs)
	}
	writeJSON(w, 200, out)
}

type accessReq struct {
	PolicyID string `json:"policyId"` // a live Conditional Access policy in the client, usually report-only
	Days     int    `json:"days"`
}

// impactAccess says who a Conditional Access policy has stopped, or would stop if
// it is report-only, over recent real sign-ins. It reads and changes nothing, and
// needs the client to keep sign-in logs (Entra ID P1 or better).
func (s *Server) impactAccess(w http.ResponseWriter, r *http.Request) {
	tenant := r.PathValue("id")
	q, err := body[accessReq](r)
	if err != nil || q.PolicyID == "" {
		fail(w, 400, errors.New(`expected {"policyId": "...", "days": 7}`))
		return
	}
	if q.Days == 0 {
		q.Days = 7
	}
	if t, err := s.Store.Tenant(tenant); err != nil || t == nil {
		fail(w, 404, errors.New("unknown tenant"))
		return
	}
	rep, err := impact.AccessFromGraph(r.Context(), s.Engine.Reader(tenant), q.PolicyID, q.Days, time.Now())
	if err != nil {
		code := 502
		if strings.Contains(err.Error(), "between 1 and 30") {
			code = 400
		}
		fail(w, code, fmt.Errorf("read the sign-in history: %w", err))
		return
	}
	writeJSON(w, 200, rep)
}
