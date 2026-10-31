package engine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/rollout"
)

const (
	gA = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	gB = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	gX = "cccccccc-cccc-cccc-cccc-cccccccccccc"
)

func asg(target map[string]any) map[string]any {
	return map[string]any{"id": "a-" + fmtAny(target), "target": target}
}
func fmtAny(t map[string]any) string { b, _ := json.Marshal(t); return string(b) }

func liveAssignments() []any {
	return []any{
		asg(map[string]any{"@odata.type": tGroup, "groupId": gA, "deviceAndAppManagementAssignmentFilterId": "filter-1", "deviceAndAppManagementAssignmentFilterType": "include"}),
		asg(map[string]any{"@odata.type": tExclude, "groupId": gX}),
	}
}

func targets(w *write) []map[string]any {
	var out []map[string]any
	for _, a := range w.Body["assignments"].([]any) {
		out = append(out, a.(map[string]any)["target"].(map[string]any))
	}
	return out
}

func TestCurrentAssignmentReadsGroupsAndEveryone(t *testing.T) {
	f := newFakeGraph(t)
	f.lists[compPath+"/c1/assignments"] = liveAssignments()
	e := engineFor(t, f, library(t, nil), true)
	a, err := GraphAssigner{e}.Current(context.Background(), "t", string(catalog.KindCompliance), "c1")
	if err != nil || len(a.Groups) != 1 || a.Groups[0] != gA || a.Virtual != "" {
		t.Fatalf("%v %+v", err, a)
	}
	f.lists[compPath+"/c2/assignments"] = []any{asg(map[string]any{"@odata.type": tAllDevice})}
	a, _ = GraphAssigner{e}.Current(context.Background(), "t", string(catalog.KindCompliance), "c2")
	if a.Virtual != rollout.AllDevices {
		t.Fatalf("%+v", a)
	}
}

func TestAddingARingKeepsExclusionsAndExistingFilters(t *testing.T) {
	f := newFakeGraph(t)
	f.lists[compPath+"/c1/assignments"] = liveAssignments()
	e := engineFor(t, f, library(t, nil), false)
	err := GraphAssigner{e}.Set(context.Background(), "t", string(catalog.KindCompliance), "c1", rollout.Assignment{Groups: []string{gA, gB}})
	if err != nil {
		t.Fatal(err)
	}
	w := f.wrote("POST", compPath+"/c1/assign")
	if w == nil {
		t.Fatal("no assign call")
	}
	var excl, keptFilter, added bool
	for _, tg := range targets(w) {
		switch {
		case tg["@odata.type"] == tExclude && tg["groupId"] == gX:
			excl = true
		case tg["groupId"] == gA && tg["deviceAndAppManagementAssignmentFilterId"] == "filter-1":
			keptFilter = true
		case tg["groupId"] == gB && tg["@odata.type"] == tGroup:
			added = true
		}
	}
	if !excl || !keptFilter || !added || len(targets(w)) != 3 {
		t.Fatalf("exclusions and filters survive, the new ring is added: %v", targets(w))
	}
}

func TestEveryoneReplacesTheGroupsButNeverTheExclusions(t *testing.T) {
	f := newFakeGraph(t)
	f.lists[iosPath+"/p1/assignments"] = liveAssignments()
	e := engineFor(t, f, library(t, nil), false)
	if err := (GraphAssigner{e}).Set(context.Background(), "t", string(catalog.KindIOSAppProtection), "p1", rollout.Assignment{Virtual: rollout.AllUsers}); err != nil {
		t.Fatal(err)
	}
	w := f.wrote("POST", iosPath+"/p1/assign")
	var types []string
	for _, tg := range targets(w) {
		types = append(types, tg["@odata.type"].(string))
	}
	got := strings.Join(types, ",")
	if !strings.Contains(got, tAllUsers) || !strings.Contains(got, tExclude) || strings.Contains(got, tGroup) {
		t.Fatalf("%s", got)
	}
}

func TestShrinkingBackRemovesOnlyWhatTheRolloutAdded(t *testing.T) {
	f := newFakeGraph(t)
	f.lists[compPath+"/c1/assignments"] = []any{
		asg(map[string]any{"@odata.type": tGroup, "groupId": gA}),
		asg(map[string]any{"@odata.type": tGroup, "groupId": gB}),
	}
	e := engineFor(t, f, library(t, nil), false)
	_ = GraphAssigner{e}.Set(context.Background(), "t", string(catalog.KindCompliance), "c1", rollout.Assignment{Groups: []string{gA}})
	tg := targets(f.wrote("POST", "/c1/assign"))
	if len(tg) != 1 || tg[0]["groupId"] != gA {
		t.Fatalf("a revert must drop the ring's group: %v", tg)
	}
}

func TestConditionalAccessRingsGoThroughTheRevertibleWritePath(t *testing.T) {
	f := newFakeGraph(t)
	caPath := "/v1.0/identity/conditionalAccess/policies"
	f.lists[caPath] = []any{map[string]any{"id": "ca1", "displayName": "CA", "state": "enabledForReportingButNotEnforced",
		"conditions": map[string]any{"users": map[string]any{"includeUsers": []any{"All"}, "excludeGroups": []any{gX}}}}}
	e := engineFor(t, f, library(t, nil), false)
	a := GraphAssigner{e}
	cur, _ := a.Current(context.Background(), "t", string(catalog.KindConditionalAccess), "ca1")
	if cur.Virtual != rollout.AllUsers {
		t.Fatalf("%+v", cur)
	}
	if err := a.Set(context.Background(), "t", string(catalog.KindConditionalAccess), "ca1", rollout.Assignment{Groups: []string{gA}}); err != nil {
		t.Fatal(err)
	}
	w := f.wrote("PATCH", "/ca1")
	if w == nil {
		t.Fatal("no patch")
	}
	users := w.Body["conditions"].(map[string]any)["users"].(map[string]any)
	if len(users["includeUsers"].([]any)) != 0 || users["includeGroups"].([]any)[0] != gA || users["excludeGroups"].([]any)[0] != gX {
		t.Fatalf("staged to the group, exclusions kept: %v", users)
	}
	h, _ := e.Store.History("t", string(catalog.KindConditionalAccess), "ca1")
	if len(h) == 0 {
		t.Fatal("a Conditional Access ring must leave a before and after version so it can be reverted")
	}
}

func TestUnsupportedKindsAndReadOnlyAreRefused(t *testing.T) {
	f := newFakeGraph(t)
	e := engineFor(t, f, library(t, nil), true)
	if err := (GraphAssigner{e}).Set(context.Background(), "t", "named-locations", "x", rollout.Assignment{}); err == nil {
		t.Fatal("named locations have no assignment")
	}
	if err := (GraphAssigner{e}).Set(context.Background(), "t", string(catalog.KindCompliance), "c1", rollout.Assignment{Groups: []string{gA}}); err == nil {
		t.Fatal("a read only credential cannot assign")
	}
	if len(f.writes) != 0 {
		t.Fatal("nothing may be written")
	}
}
