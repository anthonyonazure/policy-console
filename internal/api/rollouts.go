package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/impact"
	"github.com/anthonyonazure/policy-console/internal/rollout"
	"github.com/anthonyonazure/policy-console/internal/store"
)

type rolloutReq struct {
	PlanID     string     `json:"planId"`
	Kind       string     `json:"kind"`
	ObjectID   string     `json:"objectId"`
	ObjectName string     `json:"objectName"`
	TemplateID string     `json:"templateId"` // needed for the compliance gate
	RingGroups [][]string `json:"ringGroups"`
	Everyone   string     `json:"everyone"`
	StartAt    string     `json:"startAt"` // RFC 3339; empty means now
	Hash       string     `json:"hash"`    // from the preview, required to create
}

func (q rolloutReq) toRequest(tenant, actor string) (rollout.Request, error) {
	req := rollout.Request{TenantID: tenant, PlanID: q.PlanID, Kind: q.Kind, ObjectID: q.ObjectID, ObjectName: q.ObjectName, Actor: actor,
		TemplateID: q.TemplateID, Binding: rollout.Binding{RingGroups: q.RingGroups, Everyone: q.Everyone}}
	if q.StartAt != "" {
		t, err := time.Parse(time.RFC3339, q.StartAt)
		if err != nil {
			return req, errors.New("startAt must be an RFC 3339 time such as 2026-11-02T09:00:00Z")
		}
		req.StartAt = t
	}
	if q.Kind == "" || q.ObjectID == "" {
		return req, errors.New("kind and objectId say which policy to roll out")
	}
	return req, nil
}

func (s *Server) rolloutPlans(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, rollout.Plans)
}

func (s *Server) rolloutReady(w http.ResponseWriter) bool {
	if s.Rollouts == nil {
		fail(w, 503, errors.New("staged rollouts are not configured"))
		return false
	}
	return true
}

// rolloutPreview shows when each ring would start and what it needs. It writes nothing.
func (s *Server) rolloutPreview(w http.ResponseWriter, r *http.Request) {
	if !s.rolloutReady(w) {
		return
	}
	q, err := body[rolloutReq](r)
	if err != nil {
		fail(w, 400, errors.New("expected a rollout request"))
		return
	}
	req, err := q.toRequest(r.PathValue("id"), actor(r))
	if err != nil {
		fail(w, 400, err)
		return
	}
	sch, err := s.Rollouts.Preview(req)
	if err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, 200, sch)
}

// rolloutCreate starts the rollout the person previewed. Starting the everyone
// ring is a bigger decision, so when approvers are configured only they may start
// a plan that ends at everyone.
func (s *Server) rolloutCreate(w http.ResponseWriter, r *http.Request) {
	if !s.rolloutReady(w) {
		return
	}
	q, err := body[rolloutReq](r)
	if err != nil {
		fail(w, 400, errors.New("expected a rollout request"))
		return
	}
	tenant := r.PathValue("id")
	if t, err := s.Store.Tenant(tenant); err != nil || t == nil {
		fail(w, 404, errors.New("unknown tenant"))
		return
	}
	req, err := q.toRequest(tenant, actor(r))
	if err != nil {
		fail(w, 400, err)
		return
	}
	ro, err := s.Rollouts.Create(r.Context(), req, q.Hash)
	switch {
	case errors.Is(err, rollout.ErrNotConfirmed):
		fail(w, 409, err)
	case errors.Is(err, store.ErrPayloadBusy):
		fail(w, 409, err)
	case err != nil:
		fail(w, 400, err)
	default:
		writeJSON(w, 201, ro)
	}
}

func (s *Server) listRollouts(w http.ResponseWriter, r *http.Request) {
	tenant := r.PathValue("id") // empty for the fleet wide list
	ros, err := s.Store.Rollouts(tenant, r.URL.Query().Get("active") == "true")
	if err != nil {
		fail(w, 500, err)
		return
	}
	if ros == nil {
		ros = []store.Rollout{}
	}
	writeJSON(w, 200, ros)
}

func (s *Server) getRollout(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, 400, errors.New("bad id"))
		return
	}
	ro, err := s.Store.Rollout(id)
	if err != nil || ro == nil {
		fail(w, 404, errors.New("no such rollout"))
		return
	}
	writeJSON(w, 200, ro)
}

type rolloutAction struct {
	Revert bool `json:"revert"` // cancel only: put the earlier assignment back
	Ring   int  `json:"ring"`   // approve only
}

func (s *Server) rolloutControl(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.rolloutReady(w) {
			return
		}
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			fail(w, 400, errors.New("bad id"))
			return
		}
		a, _ := body[rolloutAction](r)
		who := actor(r)
		switch action {
		case "pause":
			err = s.Rollouts.Pause(id, who)
		case "resume":
			err = s.Rollouts.Resume(id, who)
		case "cancel":
			err = s.Rollouts.Cancel(r.Context(), id, who, a.Revert)
		case "approve":
			if !s.isApprover(who) {
				fail(w, 403, errors.New("only an approver can approve a ring"))
				return
			}
			err = s.Rollouts.Approve(id, a.Ring, who)
		}
		if err != nil {
			fail(w, 400, err)
			return
		}
		writeJSON(w, 200, map[string]any{action: id})
	}
}

// isApprover is true for everyone when no approvers are configured, otherwise
// only for the listed people. Approval is the one decision a rollout cannot skip.
func (s *Server) isApprover(who string) bool {
	if len(s.Cfg.Approvers) == 0 {
		return true
	}
	for _, a := range s.Cfg.Approvers {
		if strings.EqualFold(a, who) {
			return true
		}
	}
	return false
}

// ImpactChecker supplies the compliance gate: the predicted share of the client's
// devices that would comply with the policy being rolled out.
func (s *Server) ImpactChecker() rollout.Checker { return impactChecker{s} }

type impactChecker struct{ s *Server }

func (c impactChecker) CompliantPercent(ctx context.Context, tenant string, ro *store.Rollout) (int, error) {
	// Once the policy is live and devices have reported, the real results beat any prediction.
	if ro.Kind == string(catalog.KindCompliance) && ro.ObjectID != "" && c.s.Engine != nil && c.s.Engine.NewGraph != nil {
		if obs, err := impact.ObservedFromGraph(ctx, c.s.Engine.Reader(tenant), ro.ObjectID); err == nil {
			if pct, ok := obs.PercentCompliant(); ok {
				return pct, nil
			}
		}
	}
	if c.s.Impact == nil {
		return 0, errors.New("device data is not available")
	}
	if ro.TemplateID == "" {
		return 0, errors.New("this rollout has no template, so compliance cannot be predicted")
	}
	t := c.s.Cat.Get(ro.TemplateID)
	if t == nil || t.Kind != catalog.KindCompliance {
		return 0, errors.New("the compliance gate needs a compliance policy template")
	}
	cfg, platform, np, err := impact.ConfigFromPolicy(t.Body)
	if err != nil {
		return 0, err
	}
	devices, err := c.s.Impact.Devices(ctx, tenant)
	if err != nil {
		return 0, err
	}
	res := impact.Evaluate(platform, cfg, np, devices, time.Now().UTC())
	if res.Counts.Active == 0 {
		return 0, fmt.Errorf("no active %s devices to judge", platform)
	}
	return res.Counts.PercentOK, nil
}
