package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/config"
	"github.com/anthonyonazure/policy-console/internal/engine"
	"github.com/anthonyonazure/policy-console/internal/store"
)

func buildoutServer(t *testing.T, readOnly bool) *Server {
	t.Helper()
	dir := t.TempDir()
	put := func(cat, name, body string) {
		_ = os.MkdirAll(filepath.Join(dir, cat), 0o755)
		_ = os.WriteFile(filepath.Join(dir, cat, name), []byte(body), 0o644)
	}
	put("intune", "w.json", `{"name":"Win cfg","platforms":"windows10","settings":[{"id":"0"}]}`)
	put("pack-compliance", "c.json", `{"@odata.type":"#microsoft.graph.windows10CompliancePolicy","displayName":"Win comp"}`)
	cat, err := catalog.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	_ = db.UpsertTenant(store.Tenant{ID: "t1", Name: "Acme", Status: "connected"})
	return &Server{Cfg: config.Config{ReadOnly: readOnly}, Store: db, Cat: cat, Engine: &engine.Engine{Store: db, Catalog: cat}}
}

func stepsOf(out map[string]any) map[string]map[string]any {
	m := map[string]map[string]any{}
	for _, s := range out["steps"].([]any) {
		sm := s.(map[string]any)
		m[sm["id"].(string)] = sm
	}
	return m
}

func TestWorkingThroughABuildout(t *testing.T) {
	s := buildoutServer(t, false)
	code, out := call(t, s, "POST", "/api/tenants/t1/buildouts", `{"answers":{"platforms":["Windows"],"thirdPartyEDR":true}}`)
	if code != 201 {
		t.Fatalf("%d %v", code, out)
	}
	steps := stepsOf(out)
	if steps["discover"]["ready"] != true || steps["compliance"]["ready"] == true {
		t.Fatalf("only the first step is ready: %v", steps["compliance"])
	}
	if p, _ := s.Store.GetProfile("t1"); !p.ThirdPartyEDR {
		t.Fatal("the answers seed the client's profile, so tailoring matches what was said")
	}

	// A step cannot run before what it depends on is done.
	if c, _ := call(t, s, "POST", "/api/buildouts/1/steps/compliance/run", `{"confirm":true,"hash":"x"}`); c != 409 && c != 400 {
		t.Fatalf("a blocked step: %d", c)
	}
	// Manual and check steps are completed by a named person; a gate needs a note.
	for _, id := range []string{"discover", "foundations", "mdm-enrollment"} {
		if c, o := call(t, s, "POST", "/api/buildouts/1/steps/"+id+"/complete", `{}`); c != 200 {
			t.Fatalf("complete %s: %d %v", id, c, o)
		}
	}
	// Preview a deploy step: nothing is created, and it returns the hash to confirm.
	code, pv := call(t, s, "POST", "/api/buildouts/1/steps/compliance/preview", `{}`)
	if code != 200 || pv["hash"] == "" || pv["unassigned"] != true {
		t.Fatalf("preview: %d %v", code, pv)
	}
	if c, _ := call(t, s, "POST", "/api/buildouts/1/steps/compliance/run", `{"confirm":true,"hash":"stale"}`); c != 409 {
		t.Fatalf("a stale confirmation: %d", c)
	}
	if c, _ := call(t, s, "POST", "/api/buildouts/1/steps/compliance/run", `{"hash":"`+pv["hash"].(string)+`"}`); c != 400 {
		t.Fatalf("no confirm flag: %d", c)
	}
	// A deploy step cannot be marked done by hand; a skip needs a reason.
	if c, _ := call(t, s, "POST", "/api/buildouts/1/steps/compliance/complete", `{}`); c != 400 {
		t.Fatalf("%d", c)
	}
	if c, _ := call(t, s, "POST", "/api/buildouts/1/steps/security/skip", `{}`); c != 400 {
		t.Fatalf("a skip without a reason: %d", c)
	}
	if c, _ := call(t, s, "POST", "/api/buildouts/1/steps/security/skip", `{"reason":"client already has these"}`); c != 200 {
		t.Fatalf("%d", c)
	}
	_, got := call(t, s, "GET", "/api/buildouts/1", "")
	prog := got["progress"].(map[string]any)
	if prog["done"] != float64(4) {
		t.Fatalf("three completed and one skipped: %v", prog)
	}
	// The pilot is a gate: it needs a note saying what was checked.
	_, _ = call(t, s, "POST", "/api/buildouts/1/steps/compliance/skip", `{"reason":"test"}`)
	if c, _ := call(t, s, "POST", "/api/buildouts/1/steps/pilot/complete", `{}`); c != 400 {
		t.Fatalf("a gate without a note: %d", c)
	}
	if c, _ := call(t, s, "POST", "/api/buildouts/1/steps/pilot/complete", `{"note":"all 6 pilot devices compliant"}`); c != 200 {
		t.Fatalf("%d", c)
	}
}

func TestReadOnlyModeNeverRunsAStep(t *testing.T) {
	s := buildoutServer(t, true)
	_, _ = call(t, s, "POST", "/api/tenants/t1/buildouts", `{"answers":{"platforms":["Windows"]}}`)
	for _, id := range []string{"discover", "foundations", "mdm-enrollment"} {
		call(t, s, "POST", "/api/buildouts/1/steps/"+id+"/complete", `{}`)
	}
	if c, _ := call(t, s, "POST", "/api/buildouts/1/steps/compliance/run", `{"confirm":true,"hash":"x"}`); c != 403 {
		t.Fatalf("read only: %d", c)
	}
}

func TestPlanPreviewSavesNothing(t *testing.T) {
	s := buildoutServer(t, false)
	code, out := call(t, s, "POST", "/api/buildplan/preview", `{"answers":{"platforms":["Windows","iOS"],"ownership":"byod"}}`)
	if code != 200 || out["plan"] == nil {
		t.Fatalf("%d %v", code, out)
	}
	if bs, _ := s.Store.Buildouts("t1"); len(bs) != 0 {
		t.Fatal("a preview must not create a build out")
	}
	if c, _ := call(t, s, "POST", "/api/tenants/nope/buildouts", `{"answers":{}}`); c != 404 {
		t.Fatalf("unknown tenant: %d", c)
	}
	_ = strings.TrimSpace
}
