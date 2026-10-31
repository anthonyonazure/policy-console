package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/store"
)

func TestMergePatchChangesAFewSettingsAndLeavesTheRest(t *testing.T) {
	out, err := MergePatch([]byte(`{"a":1,"b":{"c":2,"d":3},"list":[1,2],"gone":true}`), []byte(`{"b":{"c":9},"list":[7],"gone":null,"new":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{`"a":1`, `"c":9`, `"d":3`, `"list":[7]`, `"new":"x"`} {
		if !strings.Contains(s, want) {
			t.Errorf("%s missing from %s", want, s)
		}
	}
	if strings.Contains(s, "gone") {
		t.Errorf("null removes a setting: %s", s)
	}
}

func setOverlay(t *testing.T, e *Engine, o store.Overlay) {
	t.Helper()
	o.TenantID = "t"
	if o.Reason == "" {
		o.Reason = "because"
	}
	if o.Owner == "" {
		o.Owner = "anthony"
	}
	if _, err := e.Store.SetOverlay(o); err != nil {
		t.Fatal(err)
	}
}

func stateOf(t *testing.T, res *CompareResult, kind catalog.Kind) string {
	t.Helper()
	for _, it := range res.Items {
		if it.Template.Kind == kind {
			return it.State
		}
	}
	return "absent"
}

func TestAnExcludedTemplateIsNotExpectedAndSaysWhy(t *testing.T) {
	f := newFakeGraph(t)
	e := engineFor(t, f, library(t, map[string]string{"c.json": complianceTpl}), true)
	cat := e.Catalog.All()[0]
	setOverlay(t, e, store.Overlay{TemplateID: cat.ID, Op: "exclude", Reason: "client does not use Windows"})
	res, err := e.Compare(context.Background(), "t", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if stateOf(t, res, catalog.KindCompliance) != "absent" || len(res.Excluded) != 1 || res.Excluded[0].Reason != "client does not use Windows" {
		t.Fatalf("%+v", res)
	}
	// An overlay that has expired no longer applies: back to the standard.
	_, _ = e.Store.SetOverlay(store.Overlay{TenantID: "t", TemplateID: cat.ID, Op: "exclude", Reason: "temporary", Owner: "a",
		ExpiresAt: time.Now().Add(-time.Hour).Format(time.RFC3339)})
	res, _ = e.Compare(context.Background(), "t", nil, "")
	if stateOf(t, res, catalog.KindCompliance) != "missing" {
		t.Fatalf("an expired exclusion must not hide a missing policy: %s", stateOf(t, res, catalog.KindCompliance))
	}
}

func TestAThirdPartyEDRFlagRemovesTheDefenderPolicies(t *testing.T) {
	f := newFakeGraph(t)
	cat := library2(t, "defender", map[string]string{"av.json": `{"name":"Defender AV","platforms":"windows10","settings":[{"id":"0"}]}`})
	e := engineFor(t, f, cat, true)
	_ = e.Store.SetProfile("t", store.Profile{ThirdPartyEDR: true})
	res, _ := e.Compare(context.Background(), "t", nil, "")
	if len(res.Items) != 0 || len(res.Excluded) != 1 || !strings.Contains(res.Excluded[0].Reason, "endpoint protection") {
		t.Fatalf("%+v", res)
	}
}

func TestAModifyOverlayChangesWhatIsExpected(t *testing.T) {
	f := newFakeGraph(t)
	e := engineFor(t, f, library(t, map[string]string{"c.json": complianceTpl}), true)
	id := e.Catalog.All()[0].ID
	setOverlay(t, e, store.Overlay{TemplateID: id, Op: "modify", Patch: `{"bitLockerEnabled":false}`, Reason: "legacy fleet"})
	f.lists[compPath] = []any{liveCompliance(map[string]any{"bitLockerEnabled": false})}
	res, _ := e.Compare(context.Background(), "t", nil, "")
	if s := stateOf(t, res, catalog.KindCompliance); s != "matches" {
		t.Fatalf("the client has what the overlay says: %s", s)
	}
	f.lists[compPath] = []any{liveCompliance(nil)} // the standard value
	res, _ = e.Compare(context.Background(), "t", nil, "")
	if s := stateOf(t, res, catalog.KindCompliance); s != "drifted" {
		t.Fatalf("this client is now off its own baseline: %s", s)
	}
}

func TestAPrefixIsDeployedAndRecognisedAgain(t *testing.T) {
	f := newFakeGraph(t)
	e := engineFor(t, f, library(t, map[string]string{"c.json": complianceTpl}), false)
	_ = e.Store.SetProfile("t", store.Profile{NamePrefix: "ACME | "})
	id := e.Catalog.All()[0].ID
	if _, err := e.Deploy(context.Background(), DeployRequest{TenantID: "t", TemplateIDs: []string{id}, Actor: "x"}); err != nil {
		t.Fatal(err)
	}
	w := f.wrote("POST", compPath)
	if w == nil || w.Body["displayName"] != "ACME | Win Compliance" {
		t.Fatalf("%v", w)
	}
	// What the service would now hold: the prefixed name plus the id marker.
	f.lists[compPath] = []any{liveCompliance(map[string]any{"displayName": "ACME | Win Compliance", "description": w.Body["description"]})}
	res, _ := e.Compare(context.Background(), "t", nil, "")
	if s := stateOf(t, res, catalog.KindCompliance); s != "matches" || len(res.Unmanaged) != 0 {
		t.Fatalf("a prefixed policy must not read as missing plus extra: %s %v", s, res.Unmanaged)
	}
}

func TestARenamedPolicyIsStillRecognisedByItsMarker(t *testing.T) {
	f := newFakeGraph(t)
	e := engineFor(t, f, library(t, map[string]string{"c.json": complianceTpl}), false)
	id := e.Catalog.All()[0].ID
	if _, err := e.Deploy(context.Background(), DeployRequest{TenantID: "t", TemplateIDs: []string{id}, Actor: "x"}); err != nil {
		t.Fatal(err)
	}
	w := f.wrote("POST", compPath)
	if d, _ := w.Body["description"].(string); !strings.Contains(d, "PCID:"+id) {
		t.Fatalf("the template id is written into the description: %q", d)
	}
	f.lists[compPath] = []any{liveCompliance(map[string]any{"displayName": "Somebody renamed this", "description": w.Body["description"]})}
	res, _ := e.Compare(context.Background(), "t", nil, "")
	if s := stateOf(t, res, catalog.KindCompliance); s == "missing" || len(res.Unmanaged) != 0 {
		t.Fatalf("renamed is not missing, and not an unknown extra: %s %v", s, res.Unmanaged)
	}
	// Deploying again does not create a duplicate beside the renamed one.
	f.writes = nil
	r2, _ := e.Deploy(context.Background(), DeployRequest{TenantID: "t", TemplateIDs: []string{id}, Actor: "x"})
	if r2.Items[0].Result != "exists" || f.wrote("POST", compPath) != nil {
		t.Fatalf("%+v", r2.Items[0])
	}
}

func TestDeployingAnExcludedTemplateIsSkippedNotCreated(t *testing.T) {
	f := newFakeGraph(t)
	e := engineFor(t, f, library(t, map[string]string{"c.json": complianceTpl}), false)
	id := e.Catalog.All()[0].ID
	setOverlay(t, e, store.Overlay{TemplateID: id, Op: "exclude", Reason: "not for them"})
	res, _ := e.Deploy(context.Background(), DeployRequest{TenantID: "t", TemplateIDs: []string{id}, Actor: "x"})
	if res.Items[0].Result != "skipped" || f.wrote("POST", compPath) != nil {
		t.Fatalf("%+v", res.Items[0])
	}
}
