package engine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/graph"
	"github.com/anthonyonazure/policy-console/internal/store"
)

const (
	compPath = "/beta/deviceManagement/deviceCompliancePolicies"
	iosPath  = "/beta/deviceAppManagement/iosManagedAppProtections"
	andPath  = "/beta/deviceAppManagement/androidManagedAppProtections"
)

// fakeGraph serves collections and records every write.
type fakeGraph struct {
	mu        sync.Mutex
	lists     map[string][]any // collection path -> live objects
	forbidden map[string]bool  // collection path -> 403
	writes    []write
	srv       *httptest.Server
}

type write struct {
	Method, Path string
	Body         map[string]any
}

func newFakeGraph(t *testing.T) *fakeGraph {
	f := &fakeGraph{lists: map[string][]any{}, forbidden: map[string]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGraph) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := r.URL.Path
	if r.Method == http.MethodGet {
		if f.forbidden[path] {
			http.Error(w, `{"error":"forbidden"}`, 403)
			return
		}
		if items, ok := f.lists[path]; ok {
			_ = json.NewEncoder(w).Encode(map[string]any{"value": items})
			return
		}
		// A single object: /collection/<id>
		if i := strings.LastIndex(path, "/"); i > 0 {
			for _, o := range f.lists[path[:i]] {
				if m, _ := o.(map[string]any); m["id"] == path[i+1:] {
					_ = json.NewEncoder(w).Encode(m)
					return
				}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{}})
		return
	}
	b, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(b, &body)
	f.writes = append(f.writes, write{r.Method, path, body})
	switch {
	case strings.HasSuffix(path, "/targetApps"), r.Method == http.MethodPatch:
		w.WriteHeader(204)
	default:
		out := map[string]any{"id": "new-id"}
		for k, v := range body {
			out[k] = v
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(out)
	}
}

func (f *fakeGraph) wrote(method, suffix string) *write {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.writes {
		if f.writes[i].Method == method && strings.HasSuffix(f.writes[i].Path, suffix) {
			return &f.writes[i]
		}
	}
	return nil
}

func library(t *testing.T, files map[string]string) *catalog.Catalog {
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, "intune", name)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c, err := catalog.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// library2 is library with a chosen category folder.
func library2(t *testing.T, category string, files map[string]string) *catalog.Catalog {
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, category, name)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c, err := catalog.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func engineFor(t *testing.T, f *fakeGraph, cat *catalog.Catalog, readOnly bool) *Engine {
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &Engine{Store: db, Catalog: cat, NewGraph: func(string) *graph.Client { return graph.NewForTest(f.srv.URL, readOnly) }}
}

const complianceTpl = `{
 "@odata.type":"#microsoft.graph.windows10CompliancePolicy","displayName":"Win Compliance","description":"OIBID:1",
 "passwordRequired":true,"bitLockerEnabled":true,
 "scheduledActionsForRule":[{"ruleName":null,"scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0}]}]}`

// What the service returns for the same policy: ids, links, a version, assignments.
func liveCompliance(over map[string]any) map[string]any {
	o := map[string]any{
		"@odata.type": "#microsoft.graph.windows10CompliancePolicy", "@odata.id": "x", "id": "c1", "version": 7,
		"displayName": "Win Compliance", "description": "OIBID:1", "passwordRequired": true, "bitLockerEnabled": true,
		"createdDateTime@odata.type": "#DateTimeOffset", "createdDateTime": "2024", "assignments": []any{},
		"scheduledActionsForRule": []any{map[string]any{"id": "r1", "@odata.id": "y", "ruleName": nil,
			"scheduledActionConfigurations": []any{map[string]any{"id": "a1", "actionType": "block", "gracePeriodHours": 0}}}},
	}
	for k, v := range over {
		o[k] = v
	}
	return o
}

const iosTpl = `{"@odata.type":"#microsoft.graph.iosManagedAppProtection","displayName":"iOS BYOD","pinRequired":true,
 "apps":[{"mobileAppIdentifier":{"@odata.type":"#microsoft.graph.iosMobileAppIdentifier","bundleId":"com.b"}},
         {"mobileAppIdentifier":{"@odata.type":"#microsoft.graph.iosMobileAppIdentifier","bundleId":"com.a"}}]}`

func TestComplianceComparesAsMatchDriftOrMissing(t *testing.T) {
	f := newFakeGraph(t)
	cat := library(t, map[string]string{"c.json": complianceTpl})
	e := engineFor(t, f, cat, true)

	state := func() string {
		res, err := e.Compare(context.Background(), "t", nil, "")
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range res.Items {
			if it.Template.Kind == catalog.KindCompliance {
				if it.State == "drifted" {
					t.Logf("changes: %+v", it.Changes)
				}
				return it.State
			}
		}
		t.Fatal("compliance template not compared")
		return ""
	}
	if s := state(); s != "missing" {
		t.Fatalf("empty tenant: %s", s)
	}
	f.lists[compPath] = []any{liveCompliance(nil)}
	if s := state(); s != "matches" {
		t.Fatalf("server bookkeeping must not read as drift: %s", s)
	}
	f.lists[compPath] = []any{liveCompliance(map[string]any{"bitLockerEnabled": false})}
	if s := state(); s != "drifted" {
		t.Fatalf("a changed setting is drift: %s", s)
	}
}

func TestAppProtectionAppOrderIsNotDrift(t *testing.T) {
	f := newFakeGraph(t)
	cat := library(t, map[string]string{"i.json": iosTpl})
	e := engineFor(t, f, cat, true)
	f.lists[iosPath] = []any{map[string]any{"id": "p1", "@odata.type": "#microsoft.graph.iosManagedAppProtection", "displayName": "iOS BYOD",
		"pinRequired": true, "deployedAppCount": 2, "version": "\"abc\"",
		"apps": []any{
			map[string]any{"id": "com.a", "version": "1", "mobileAppIdentifier": map[string]any{"@odata.type": "#microsoft.graph.iosMobileAppIdentifier", "bundleId": "com.a"}},
			map[string]any{"id": "com.b", "version": "2", "mobileAppIdentifier": map[string]any{"@odata.type": "#microsoft.graph.iosMobileAppIdentifier", "bundleId": "com.b"}},
		}}}
	res, err := e.Compare(context.Background(), "t", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range res.Items {
		if it.Template.Kind == catalog.KindIOSAppProtection && it.State != "matches" {
			t.Fatalf("different app order and service ids must match, got %s: %+v", it.State, it.Changes)
		}
	}
}

func TestAKindTheAppCannotReadIsNotReportedMissing(t *testing.T) {
	f := newFakeGraph(t)
	f.forbidden[iosPath] = true
	cat := library(t, map[string]string{"i.json": iosTpl, "c.json": complianceTpl})
	e := engineFor(t, f, cat, true)
	res, err := e.Compare(context.Background(), "t", nil, "")
	if err != nil {
		t.Fatalf("one forbidden kind must not fail the whole comparison: %v", err)
	}
	if len(res.Unreadable) != 1 || res.Unreadable[0] != string(catalog.KindIOSAppProtection) {
		t.Fatalf("unreadable = %v", res.Unreadable)
	}
	for _, it := range res.Items {
		switch it.Template.Kind {
		case catalog.KindIOSAppProtection:
			if it.State != "error" {
				t.Fatalf("an unreadable kind must be 'error', not %q (that would read as a missing policy)", it.State)
			}
		case catalog.KindCompliance:
			if it.State != "missing" {
				t.Fatalf("readable kinds are still judged: %s", it.State)
			}
		}
	}
}

func TestDeployCreatesComplianceCleanlyAndNeverAssigns(t *testing.T) {
	f := newFakeGraph(t)
	cat := library(t, map[string]string{"c.json": complianceTpl})
	e := engineFor(t, f, cat, false)
	id := cat.All()[0].ID
	res, err := e.Deploy(context.Background(), DeployRequest{TenantID: "t", TemplateIDs: []string{id}, Actor: "test", Rollout: RolloutAll})
	if err != nil {
		t.Fatal(err)
	}
	if res.Items[0].Result != "created" || !strings.Contains(res.Items[0].Detail, "NOT assigned") {
		t.Fatalf("%+v", res.Items[0])
	}
	w := f.wrote("POST", compPath)
	if w == nil {
		t.Fatal("no create call")
	}
	if _, ok := w.Body["id"]; ok {
		t.Error("id must not be sent")
	}
	if _, ok := w.Body["@odata.type"]; !ok {
		t.Error("the compliance type must be sent, or the service cannot tell which policy this is")
	}
	rules, _ := w.Body["scheduledActionsForRule"].([]any)
	if len(rules) != 1 {
		t.Fatalf("actions on non-compliance must be created with the policy: %v", w.Body)
	}
	if f.wrote("POST", "/assign") != nil {
		t.Fatal("a compliance policy must not be assigned by a deploy yet")
	}
}

func TestDeployAppProtectionCreatesThenAttachesAppsByIdentifier(t *testing.T) {
	f := newFakeGraph(t)
	cat := library(t, map[string]string{"i.json": iosTpl})
	e := engineFor(t, f, cat, false)
	res, err := e.Deploy(context.Background(), DeployRequest{TenantID: "t", TemplateIDs: []string{cat.All()[0].ID}, Actor: "test"})
	if err != nil || res.Items[0].Result != "created" {
		t.Fatalf("%v %+v", err, res)
	}
	create := f.wrote("POST", iosPath)
	if create == nil {
		t.Fatal("no create")
	}
	if _, has := create.Body["apps"]; has {
		t.Error("apps are not accepted on create")
	}
	attach := f.wrote("POST", "/new-id/targetApps")
	if attach == nil {
		t.Fatal("apps were never attached")
	}
	apps, _ := attach.Body["apps"].([]any)
	if len(apps) != 2 {
		t.Fatalf("apps: %v", attach.Body)
	}
	for _, a := range apps {
		m := a.(map[string]any)
		if len(m) != 1 || m["mobileAppIdentifier"] == nil {
			t.Fatalf("only the identifier is sent: %v", m)
		}
	}
	if !strings.Contains(res.Items[0].Detail, "2 apps attached") {
		t.Fatal(res.Items[0].Detail)
	}
}

func TestDeployLeavesAnExistingNameAloneAndRefusesWhenItCannotLook(t *testing.T) {
	f := newFakeGraph(t)
	cat := library(t, map[string]string{"c.json": complianceTpl})
	e := engineFor(t, f, cat, false)
	f.lists[compPath] = []any{liveCompliance(nil)}
	res, _ := e.Deploy(context.Background(), DeployRequest{TenantID: "t", TemplateIDs: []string{cat.All()[0].ID}, Actor: "t"})
	if res.Items[0].Result != "exists" || f.wrote("POST", compPath) != nil {
		t.Fatalf("an existing policy must never be overwritten: %+v", res.Items[0])
	}

	f2 := newFakeGraph(t)
	f2.forbidden[compPath] = true
	e2 := engineFor(t, f2, cat, false)
	res, _ = e2.Deploy(context.Background(), DeployRequest{TenantID: "t", TemplateIDs: []string{cat.All()[0].ID}, Actor: "t"})
	if res.Items[0].Result != "failed" || f2.wrote("POST", compPath) != nil {
		t.Fatalf("without read access the console cannot know the policy is absent, so it must not create: %+v", res.Items[0])
	}
}

func TestReadOnlyModeRefusesToCreate(t *testing.T) {
	f := newFakeGraph(t)
	cat := library(t, map[string]string{"c.json": complianceTpl})
	e := engineFor(t, f, cat, true)
	res, _ := e.Deploy(context.Background(), DeployRequest{TenantID: "t", TemplateIDs: []string{cat.All()[0].ID}, Actor: "t"})
	if res.Items[0].Result != "failed" || len(f.writes) != 0 {
		t.Fatalf("%+v writes=%d", res.Items[0], len(f.writes))
	}
}

func TestRevertOfComplianceSaysWhatItCouldNotRestore(t *testing.T) {
	f := newFakeGraph(t)
	f.lists[compPath] = []any{liveCompliance(nil)}
	e := engineFor(t, f, library(t, map[string]string{"c.json": complianceTpl}), false)
	body, _ := json.Marshal(liveCompliance(map[string]any{"passwordRequired": false}))
	item, err := e.Write(context.Background(), "t", catalog.KindCompliance, "c1", body, "modify", "tester", "")
	if err != nil {
		t.Fatal(err)
	}
	w := f.wrote("PATCH", "/c1")
	if w == nil {
		t.Fatal("no patch")
	}
	if _, has := w.Body["scheduledActionsForRule"]; has {
		t.Error("PATCH cannot carry the actions on non-compliance")
	}
	if !strings.Contains(item.Detail, "actions on non-compliance were not restored") {
		t.Fatalf("a partial restore must say so: %q", item.Detail)
	}
}

func TestSnapshotCapturesNewKindsAndDegradesOnForbidden(t *testing.T) {
	f := newFakeGraph(t)
	f.lists[compPath] = []any{liveCompliance(nil)}
	f.forbidden[andPath] = true
	e := engineFor(t, f, library(t, nil), true)
	res, err := e.Snapshot(context.Background(), "t", "scheduled", "test")
	if err != nil {
		t.Fatal(err)
	}
	if res.Captured != 1 || len(res.Errors) != 1 || !strings.Contains(res.Errors[0], string(catalog.KindAndroidAppProtection)) {
		t.Fatalf("%+v", res)
	}
	h, _ := e.Store.History("t", string(catalog.KindCompliance), "c1")
	if len(h) != 1 {
		t.Fatalf("compliance not versioned: %d", len(h))
	}
}

func TestABadCredentialFailsTheComparisonInsteadOfLookingLikeNoPermission(t *testing.T) {
	f := newFakeGraph(t)
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "expired", 401) })
	e := engineFor(t, f, library(t, map[string]string{"c.json": complianceTpl}), true)
	if _, err := e.Compare(context.Background(), "t", nil, ""); err == nil {
		t.Fatal("a 401 must fail the comparison; treating it as unreadable would read as 'all fixed'")
	}
}

func TestIfNothingIsReadableTheComparisonFails(t *testing.T) {
	f := newFakeGraph(t)
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 403) })
	e := engineFor(t, f, library(t, nil), true)
	if _, err := e.Compare(context.Background(), "t", nil, ""); err == nil || !strings.Contains(err.Error(), "not permitted to read anything") {
		t.Fatalf("%v", err)
	}
}

// One unreadable kind must not switch off deletion detection for the others.
func TestADeletedPolicyIsStillNoticedWhenAnotherKindIsUnreadable(t *testing.T) {
	f := newFakeGraph(t)
	e := engineFor(t, f, library(t, nil), true)
	f.lists[compPath] = []any{liveCompliance(nil)}
	if _, err := e.Snapshot(context.Background(), "t", "scheduled", "test"); err != nil {
		t.Fatal(err)
	}
	f.lists[compPath] = []any{} // the compliance policy is deleted in the tenant
	f.forbidden[andPath] = true // and an unrelated kind cannot be read
	res, err := e.Snapshot(context.Background(), "t", "scheduled", "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Errors) != 1 {
		t.Fatalf("errors: %v", res.Errors)
	}
	h, _ := e.Store.History("t", string(catalog.KindCompliance), "c1")
	if len(h) != 2 || !h[0].Deleted {
		t.Fatalf("the deletion must be recorded: %+v", h)
	}
}

func TestAKindThatFailedToReadIsNeverMarkedDeleted(t *testing.T) {
	f := newFakeGraph(t)
	e := engineFor(t, f, library(t, nil), true)
	f.lists[compPath] = []any{liveCompliance(nil)}
	_, _ = e.Snapshot(context.Background(), "t", "scheduled", "test")
	f.forbidden[compPath] = true
	_, _ = e.Snapshot(context.Background(), "t", "scheduled", "test")
	h, _ := e.Store.History("t", string(catalog.KindCompliance), "c1")
	if len(h) != 1 {
		t.Fatalf("an unreadable kind says nothing about deletions: %d versions", len(h))
	}
}

// Exports often omit the actions on non-compliance, and Microsoft refuses to
// create a compliance policy without one.
func TestComplianceTemplateWithoutActionsGetsTheStandardOne(t *testing.T) {
	f := newFakeGraph(t)
	bare := `{"@odata.type":"#microsoft.graph.macOSCompliancePolicy","displayName":"Mac bare","passwordRequired":true}`
	cat := library(t, map[string]string{"m.json": bare})
	e := engineFor(t, f, cat, false)
	if _, err := e.Deploy(context.Background(), DeployRequest{TenantID: "t", TemplateIDs: []string{cat.All()[0].ID}, Actor: "t"}); err != nil {
		t.Fatal(err)
	}
	w := f.wrote("POST", compPath)
	if w == nil {
		t.Fatal("no create")
	}
	rules, _ := w.Body["scheduledActionsForRule"].([]any)
	if len(rules) != 1 {
		t.Fatalf("expected the default rule: %v", w.Body)
	}
	cfg := rules[0].(map[string]any)["scheduledActionConfigurations"].([]any)[0].(map[string]any)
	if cfg["actionType"] != "block" || cfg["gracePeriodHours"] != float64(0) {
		t.Fatalf("default action: %v", cfg)
	}
}

func TestAVersionWithRedactedSecretsCanNeverBeWrittenBack(t *testing.T) {
	f := newFakeGraph(t)
	f.lists[compPath] = []any{liveCompliance(nil)}
	e := engineFor(t, f, library(t, nil), false)
	body := []byte(`{"@odata.type":"#microsoft.graph.windows10CompliancePolicy","displayName":"x","preSharedKey":"[redacted:abcd1234]"}`)
	_, err := e.Write(context.Background(), "t", catalog.KindCompliance, "c1", body, "revert", "tester", "")
	if err == nil || f.wrote("PATCH", "/c1") != nil {
		t.Fatalf("writing the marker over the real secret must be refused: %v", err)
	}
}

func TestReadOnlyKindsAreSnapshottedButNeverReportedAsExtra(t *testing.T) {
	f := newFakeGraph(t)
	f.lists["/beta/deviceManagement/deviceConfigurations"] = []any{map[string]any{"id": "u1", "displayName": "Windows update ring", "@odata.type": "#microsoft.graph.windowsUpdateForBusinessConfiguration"}}
	f.lists["/beta/deviceManagement/windowsAutopilotDeploymentProfiles"] = []any{map[string]any{"id": "ap1", "displayName": "Autopilot user driven"}}
	f.lists["/beta/deviceManagement/assignmentFilters"] = []any{map[string]any{"id": "f1", "displayName": "Windows 11 only"}}
	e := engineFor(t, f, library(t, map[string]string{"c.json": complianceTpl}), true)
	res, err := e.Snapshot(context.Background(), "t", "scheduled", "test")
	if err != nil || res.Captured != 3 || len(res.Errors) != 0 {
		t.Fatalf("%v %+v", err, res)
	}
	for _, k := range []catalog.Kind{catalog.KindDeviceConfig, catalog.KindAutopilotProfile, catalog.KindAssignmentFilter} {
		objs, _ := e.Store.LatestObjects("t")
		found := false
		for _, o := range objs {
			if o.Kind == string(k) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s was not recorded in history", k)
		}
	}
	cmp, err := e.Compare(context.Background(), "t", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmp.Unmanaged) != 0 {
		t.Fatalf("an update ring is not an unknown extra when the standard says nothing about update rings: %+v", cmp.Unmanaged)
	}
}
