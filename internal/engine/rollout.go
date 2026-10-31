package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/graph"
)

// Rollout controls how a newly created policy is targeted.
//
//   - pilot: Conditional Access applies only to the pilot group instead of
//     everyone; Intune policies are assigned to the pilot group only.
//   - all:   Conditional Access keeps the template's targeting; Intune policies
//     are assigned to all devices.
//   - none:  nothing is assigned. An Intune policy created this way does
//     nothing until someone assigns it, which is why the UI never defaults here.
const (
	RolloutPilot = "pilot"
	RolloutAll   = "all"
	RolloutNone  = "none"
)

// applyPilot narrows a Conditional Access policy that targets everyone to the
// pilot group. Policies that target roles, guests or specific groups are left
// alone, since shrinking "all administrators" to a pilot group would leave the
// rest of the administrators unprotected rather than untouched.
func applyPilot(body []byte, pilotGroup string) ([]byte, string, error) {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, "", err
	}
	cond, _ := doc["conditions"].(map[string]any)
	users, _ := cond["users"].(map[string]any)
	if users == nil {
		return body, "no user targeting to narrow", nil
	}
	inc, _ := users["includeUsers"].([]any)
	all := false
	for _, u := range inc {
		if s, _ := u.(string); strings.EqualFold(s, "All") {
			all = true
		}
	}
	if !all {
		return body, "targets specific roles, guests or groups; applied as written, not narrowed to the pilot", nil
	}
	users["includeUsers"] = []any{}
	groups, _ := users["includeGroups"].([]any)
	users["includeGroups"] = append(groups, pilotGroup)
	out, err := json.MarshalIndent(doc, "", "  ")
	return out, "narrowed from all users to the pilot group", err
}

// assign targets an Intune configuration policy at a group or at all devices.
func assign(ctx context.Context, g *graph.Client, policyID, rollout, pilotGroup string) error {
	var target map[string]any
	switch rollout {
	case RolloutPilot:
		target = map[string]any{"@odata.type": "#microsoft.graph.groupAssignmentTarget", "groupId": pilotGroup}
	case RolloutAll:
		target = map[string]any{"@odata.type": "#microsoft.graph.allDevicesAssignmentTarget"}
	default:
		return nil
	}
	body, _ := json.Marshal(map[string]any{"assignments": []any{map[string]any{"target": target}}})
	_, err := g.Post(ctx, catalog.Collections[catalog.KindConfigPolicy].URI+"/"+policyID+"/assign", body)
	return err
}

// ReportOnlySince returns when a Conditional Access policy last entered
// report-only, from the console's own version history, and whether it is
// report-only now. The history is the evidence: a policy the console has never
// captured has no known start and is treated as not ready.
func (e *Engine) ReportOnlySince(tenantID, objectID string) (time.Time, bool, error) {
	hist, err := e.Store.History(tenantID, string(catalog.KindConditionalAccess), objectID)
	if err != nil || len(hist) == 0 {
		return time.Time{}, false, err
	}
	var since time.Time
	for i, h := range hist { // newest first
		v, err := e.Store.VersionBody(tenantID, string(catalog.KindConditionalAccess), objectID, h.Version)
		if err != nil || v == nil || v.Deleted {
			break
		}
		var doc struct {
			State string `json:"state"`
		}
		_ = json.Unmarshal(v.Body, &doc)
		if doc.State != "enabledForReportingButNotEnforced" {
			if i == 0 {
				return time.Time{}, false, nil
			}
			break
		}
		if t, err := time.Parse(time.RFC3339, h.CapturedAt); err == nil {
			since = t
		}
	}
	return since, !since.IsZero(), nil
}

// Enforce switches a report-only Conditional Access policy on. It refuses until
// the policy has been report-only for minHours, the observation window the
// library recommends before a policy starts blocking real people. An override
// is possible but must carry a reason, which lands in the run log.
func (e *Engine) Enforce(ctx context.Context, tenantID, objectID string, minHours int, overrideReason, actor string) (*RunItemResult, error) {
	since, reportOnly, err := e.ReportOnlySince(tenantID, objectID)
	if err != nil {
		return nil, err
	}
	if !reportOnly {
		return nil, fmt.Errorf("this policy is not report-only in the console's history; take a snapshot first if it was just changed in the portal")
	}
	age := time.Since(since)
	if age < time.Duration(minHours)*time.Hour && strings.TrimSpace(overrideReason) == "" {
		return nil, fmt.Errorf("report-only for %s; the minimum is %d hours before enforcing. Wait, or give a reason to override", age.Round(time.Minute), minHours)
	}
	detail := fmt.Sprintf("enforced after %s in report-only", age.Round(time.Minute))
	if overrideReason != "" && age < time.Duration(minHours)*time.Hour {
		detail += "; minimum overridden: " + overrideReason
	}
	item, err := e.Write(ctx, tenantID, catalog.KindConditionalAccess, objectID, []byte(`{"state":"enabled"}`), "enforce", actor, detail)
	if err != nil {
		return nil, err
	}
	return &RunItemResult{Item: *item, ReportOnlyHours: age.Hours()}, nil
}

// RunItemResult pairs a run item with the timing that justified it.
type RunItemResult struct {
	Item            any     `json:"item"`
	ReportOnlyHours float64 `json:"reportOnlyHours"`
}

// Widen moves a piloted policy to everyone: Conditional Access drops the pilot
// group and targets all users again; Intune policies are assigned to all
// devices. Both go through Write or snapshots, so they can be reverted.
func (e *Engine) Widen(ctx context.Context, tenantID string, kind catalog.Kind, objectID, pilotGroup, actor string) (any, error) {
	g := e.NewGraph(tenantID)
	if kind == catalog.KindConfigPolicy {
		end := e.Gate.BeginWrite(tenantID)
		err := assign(ctx, g, objectID, RolloutAll, "")
		end()
		if err != nil {
			return nil, err
		}
		runID, _ := e.Store.StartRun(storeRun(tenantID, "widen", actor))
		_ = e.Store.FinishRun(runID, "assigned to all devices")
		return map[string]string{"result": "assigned to all devices"}, nil
	}
	cur, err := g.Get(ctx, catalog.Collections[kind].URI+"/"+objectID)
	if err != nil {
		return nil, err
	}
	cond, _ := cur["conditions"].(map[string]any)
	users, _ := cond["users"].(map[string]any)
	groups, _ := users["includeGroups"].([]any)
	kept := []any{}
	found := false
	for _, gr := range groups {
		if s, _ := gr.(string); s == pilotGroup {
			found = true
			continue
		}
		kept = append(kept, gr)
	}
	if !found {
		return nil, fmt.Errorf("the pilot group is not in this policy's targeting; nothing to widen")
	}
	patch := map[string]any{"conditions": map[string]any{"users": map[string]any{
		"includeUsers":  []any{"All"},
		"includeGroups": kept,
		"excludeUsers":  users["excludeUsers"],
		"excludeGroups": users["excludeGroups"],
	}}}
	body, _ := json.Marshal(patch)
	return e.Write(ctx, tenantID, kind, objectID, body, "widen", actor, "pilot group removed, now targets all users")
}
