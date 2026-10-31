package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/rollout"
	"github.com/anthonyonazure/policy-console/internal/store"
)

// GraphAssigner reads and writes who a policy is offered to. It is what staged
// rollouts use to move a policy from ring to ring.
//
// A rollout only ever changes the "include" side. Exclusions are kept exactly as
// they are, and an existing include group keeps its assignment filter.
type GraphAssigner struct{ E *Engine }

const (
	tGroup     = "#microsoft.graph.groupAssignmentTarget"
	tExclude   = "#microsoft.graph.exclusionGroupAssignmentTarget"
	tAllDevice = "#microsoft.graph.allDevicesAssignmentTarget"
	tAllUsers  = "#microsoft.graph.allLicensedUsersAssignmentTarget"
)

func (a GraphAssigner) Current(ctx context.Context, tenant, kind, objectID string) (rollout.Assignment, error) {
	k := catalog.Kind(kind)
	if k == catalog.KindConditionalAccess {
		return a.currentCA(ctx, tenant, objectID)
	}
	if _, ok := catalog.Collections[k]; !ok || !assignable(k) {
		return rollout.Assignment{}, fmt.Errorf("staged rollouts do not support %q yet", kind)
	}
	items, err := a.E.Reader(tenant).List(ctx, catalog.Collections[k].URI+"/"+objectID+"/assignments")
	if err != nil {
		return rollout.Assignment{}, err
	}
	var out rollout.Assignment
	for _, it := range items {
		t, _ := it["target"].(map[string]any)
		switch t["@odata.type"] {
		case tGroup:
			if g, _ := t["groupId"].(string); g != "" {
				out.Groups = append(out.Groups, g)
			}
		case tAllDevice:
			out.Virtual = rollout.AllDevices
		case tAllUsers:
			out.Virtual = rollout.AllUsers
		}
	}
	return out, nil
}

func assignable(k catalog.Kind) bool {
	return k == catalog.KindConfigPolicy || k == catalog.KindCompliance || isAppProtection(k)
}

func (a GraphAssigner) Set(ctx context.Context, tenant, kind, objectID string, want rollout.Assignment) error {
	k := catalog.Kind(kind)
	if k == catalog.KindConditionalAccess {
		return a.setCA(ctx, tenant, objectID, want)
	}
	if !assignable(k) {
		return fmt.Errorf("staged rollouts do not support %q yet", kind)
	}
	defer a.E.Gate.BeginWrite(tenant)()
	g := a.E.NewGraph(tenant)
	uri := catalog.Collections[k].URI + "/" + objectID

	items, err := g.List(ctx, uri+"/assignments")
	if err != nil {
		return fmt.Errorf("read the current assignment: %w", err)
	}
	wantGroup := map[string]bool{}
	for _, gid := range want.Groups {
		wantGroup[strings.ToLower(gid)] = true
	}
	var out []map[string]any
	have := map[string]bool{}
	for _, it := range items {
		t, _ := it["target"].(map[string]any)
		switch t["@odata.type"] {
		case tExclude:
			out = append(out, map[string]any{"target": t}) // exclusions are never touched
		case tGroup:
			gid, _ := t["groupId"].(string)
			if want.Virtual == "" && wantGroup[strings.ToLower(gid)] {
				out = append(out, map[string]any{"target": t}) // keeps its filter
				have[strings.ToLower(gid)] = true
			}
		}
	}
	switch want.Virtual {
	case rollout.AllDevices:
		out = append(out, map[string]any{"target": map[string]any{"@odata.type": tAllDevice}})
	case rollout.AllUsers:
		out = append(out, map[string]any{"target": map[string]any{"@odata.type": tAllUsers}})
	default:
		for _, gid := range want.Groups {
			if !have[strings.ToLower(gid)] {
				out = append(out, map[string]any{"target": map[string]any{"@odata.type": tGroup, "groupId": gid}})
				have[strings.ToLower(gid)] = true
			}
		}
	}
	body, _ := json.Marshal(map[string]any{"assignments": out})

	runID, _ := a.E.Store.StartRun(store.Run{TenantID: tenant, Action: "rollout-assign", Mode: "live", Actor: "rollout"})
	item := store.RunItem{RunID: runID, Kind: kind, ObjectID: objectID, Name: objectID}
	err = g.PostAction(ctx, uri+"/assign", body)
	if err != nil {
		item.Result, item.Detail = "failed", err.Error()
	} else {
		item.Result, item.Detail = "updated", fmt.Sprintf("assigned to %d group(s)%s", len(want.Groups), virtualNote(want.Virtual))
	}
	_ = a.E.Store.AddRunItem(item)
	_ = a.E.Store.FinishRun(runID, item.Detail)
	return err
}

func virtualNote(v string) string {
	if v == "" {
		return ""
	}
	return " and " + strings.ReplaceAll(v, "-", " ")
}

// ---- Conditional Access: the groups live inside the policy, so the change goes
// through Write and is snapshotted and revertible like any other edit. ----

func (a GraphAssigner) currentCA(ctx context.Context, tenant, id string) (rollout.Assignment, error) {
	obj, err := a.E.Reader(tenant).Get(ctx, itemURI(catalog.KindConditionalAccess, id))
	if err != nil {
		return rollout.Assignment{}, err
	}
	users := caUsers(obj)
	var out rollout.Assignment
	for _, u := range strs(users["includeUsers"]) {
		if strings.EqualFold(u, "All") {
			out.Virtual = rollout.AllUsers
		}
	}
	out.Groups = strs(users["includeGroups"])
	return out, nil
}

func (a GraphAssigner) setCA(ctx context.Context, tenant, id string, want rollout.Assignment) error {
	obj, err := a.E.NewGraph(tenant).Get(ctx, itemURI(catalog.KindConditionalAccess, id))
	if err != nil {
		return err
	}
	cond, _ := obj["conditions"].(map[string]any)
	if cond == nil {
		return fmt.Errorf("the policy has no conditions to stage")
	}
	users, _ := cond["users"].(map[string]any)
	if users == nil {
		return fmt.Errorf("the policy has no users condition to stage")
	}
	if want.Virtual == rollout.AllUsers {
		users["includeUsers"] = []any{"All"}
		users["includeGroups"] = []any{}
	} else {
		users["includeUsers"] = []any{} // staged by group: the groups are the audience
		gs := make([]any, 0, len(want.Groups))
		for _, g := range want.Groups {
			gs = append(gs, g)
		}
		users["includeGroups"] = gs
	}
	body, _ := json.Marshal(obj)
	_, err = a.E.Write(ctx, tenant, catalog.KindConditionalAccess, id, body, "rollout", "rollout", "staged by a rollout ring")
	return err
}

func caUsers(obj map[string]any) map[string]any {
	c, _ := obj["conditions"].(map[string]any)
	u, _ := c["users"].(map[string]any)
	return u
}

func strs(v any) []string {
	l, _ := v.([]any)
	var out []string
	for _, x := range l {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
