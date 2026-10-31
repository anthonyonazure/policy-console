package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/config"
	"github.com/anthonyonazure/policy-console/internal/engine"
	"github.com/anthonyonazure/policy-console/internal/graph"
	"github.com/anthonyonazure/policy-console/internal/impact"
	"github.com/anthonyonazure/policy-console/internal/store"
)

func fleetServer(t *testing.T, graphHandler http.HandlerFunc, approvers ...string) (*Server, *[]string) {
	t.Helper()
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "intune"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "intune", "w.json"), []byte(`{"name":"Win cfg","platforms":"windows10","settings":[{"id":"0"}]}`), 0o644)
	cat, err := catalog.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, id := range []string{"t1", "t2", "t3"} {
		_ = db.UpsertTenant(store.Tenant{ID: id, Name: "Client " + id, Status: "connected"})
	}
	var mu sync.Mutex
	var touched []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if r.Method == http.MethodPost {
			touched = append(touched, r.URL.Path)
		}
		mu.Unlock()
		graphHandler(w, r)
	}))
	t.Cleanup(srv.Close)
	eng := &engine.Engine{Store: db, Catalog: cat, NewGraph: func(string) *graph.Client { return graph.NewForTest(srv.URL, false) }}
	return &Server{Cfg: config.Config{Approvers: approvers}, Store: db, Cat: cat, Engine: eng}, &touched
}

func healthyGraph(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		_, _ = w.Write([]byte(`{"value":[]}`))
		return
	}
	w.WriteHeader(201)
	_, _ = w.Write([]byte(`{"id":"new"}`))
}

func templateID(s *Server) string { return s.Cat.All()[0].ID }

func TestFleetBoardPutsTheWorstClientFirst(t *testing.T) {
	s, _ := fleetServer(t, healthyGraph)
	now := time.Now()
	_, _ = s.Store.ApplyFindings("t2", []store.Finding{{TemplateID: "a", Class: "missing", Severity: "critical", Name: "A"}, {TemplateID: "b", Class: "changed", Severity: "warning", Name: "B"}}, nil, now)
	_, _ = s.Store.ApplyFindings("t3", []store.Finding{{TemplateID: "c", Class: "changed", Severity: "warning", Name: "C"}}, nil, now)
	o, _ := s.Store.OpenFindings("t3")
	_ = s.Store.Acknowledge(o[0].ID, "anthony", "known", now)
	req := httptest.NewRequest("GET", "/api/fleet", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	var rows []map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &rows)
	if len(rows) != 3 || rows[0]["tenantId"] != "t2" || rows[0]["critical"] != float64(1) {
		t.Fatalf("%v", rows)
	}
	for _, r := range rows {
		if r["tenantId"] == "t3" && (r["warning"] != float64(0) || r["acknowledgedOrSnoozed"] != float64(1)) {
			t.Fatalf("an acknowledged finding is not counted against the client: %v", r)
		}
	}
}

func fleetCall(s *Server, path, body string) (int, map[string]any) {
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestFleetApplyNeedsACanaryAndAMatchingPreview(t *testing.T) {
	s, touched := fleetServer(t, healthyGraph)
	body := func(extra string) string {
		return `{"templateIds":["` + templateID(s) + `"],"tenantIds":["t1","t2"]` + extra + `}`
	}
	if c, _ := fleetCall(s, "/api/fleet/apply/preview", body("")); c != 400 {
		t.Fatalf("several clients need a canary: %d", c)
	}
	code, pv := fleetCall(s, "/api/fleet/apply/preview", body(`,"canaryTenantId":"t2"`))
	if code != 200 || pv["order"].([]any)[0] != "t2" || len(*touched) != 0 {
		t.Fatalf("preview: %d %v writes=%v", code, pv, *touched)
	}
	if c, _ := fleetCall(s, "/api/fleet/apply", body(`,"canaryTenantId":"t2","hash":"stale","confirm":true`)); c != 409 {
		t.Fatalf("a stale confirmation: %d", c)
	}
	if c, _ := fleetCall(s, "/api/fleet/apply", body(`,"canaryTenantId":"t2","hash":"`+pv["hash"].(string)+`"`)); c != 400 {
		t.Fatalf("no confirm flag: %d", c)
	}
	if len(*touched) != 0 {
		t.Fatal("nothing may be written before a matching confirmation")
	}
	code, out := fleetCall(s, "/api/fleet/apply", body(`,"canaryTenantId":"t2","hash":"`+pv["hash"].(string)+`","confirm":true`))
	if code != 200 || out["stoppedAtCanary"] != false || len(out["clients"].([]any)) != 2 {
		t.Fatalf("%d %v", code, out)
	}
	if out["clients"].([]any)[0].(map[string]any)["tenantId"] != "t2" {
		t.Fatal("the canary goes first")
	}
	if len(*touched) != 2 {
		t.Fatalf("one policy per client: %v", *touched)
	}
}

func TestACanaryFailureStopsEveryoneElse(t *testing.T) {
	s, touched := fleetServer(t, func(w http.ResponseWriter, r *http.Request) { http.Error(w, "down", 500) })
	body := `{"templateIds":["` + templateID(s) + `"],"tenantIds":["t1","t2","t3"],"canaryTenantId":"t1"`
	_, pv := fleetCall(s, "/api/fleet/apply/preview", body+`}`)
	code, out := fleetCall(s, "/api/fleet/apply", body+`,"hash":"`+pv["hash"].(string)+`","confirm":true}`)
	if code != 200 || out["stoppedAtCanary"] != true || len(out["clients"].([]any)) != 1 {
		t.Fatalf("%d %v", code, out)
	}
	if len(*touched) != 0 {
		t.Fatalf("no other client may be touched: %v", *touched)
	}
}

func TestFleetApplyRespectsReadOnlyAndApprovers(t *testing.T) {
	s, touched := fleetServer(t, healthyGraph, "someone.else@example.com")
	body := `{"templateIds":["` + templateID(s) + `"],"tenantIds":["t1"],"hash":"x","confirm":true}`
	if c, _ := fleetCall(s, "/api/fleet/apply", body); c != 403 {
		t.Fatalf("a non approver: %d", c)
	}
	s2, _ := fleetServer(t, healthyGraph)
	s2.Cfg.ReadOnly = true
	if c, _ := fleetCall(s2, "/api/fleet/apply", body); c != 403 {
		t.Fatalf("read only: %d", c)
	}
	if len(*touched) != 0 {
		t.Fatal("nothing written")
	}
}

func TestReportsAreSavedAndSaySinceTheLastOne(t *testing.T) {
	s, _ := fleetServer(t, healthyGraph)
	// The template is missing from an empty tenant: 0 percent, one missing.
	code, first := fleetCall(s, "/api/tenants/t1/reports", `{}`)
	if code != 201 || first["percent"] != float64(0) || !strings.Contains(first["change"].(string), "first report") {
		t.Fatalf("%d %v", code, first)
	}
	_, second := fleetCall(s, "/api/tenants/t1/reports", `{}`)
	if second["change"] != "Nothing has changed since the last report." {
		t.Fatalf("%v", second)
	}
	req := httptest.NewRequest("GET", "/api/reports/1", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Client t1") || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("%d %s", w.Code, w.Header().Get("Content-Type"))
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Fatalf("a served report must forbid scripts: %q", csp)
	}
	if c, _ := fleetCall(s, "/api/tenants/nope/reports", `{}`); c != 404 {
		t.Fatalf("%d", c)
	}
	if c, _ := fleetCall(s, "/api/tenants/t1/reports", `{"baseline":"nonsense"}`); c != 400 {
		t.Fatalf("%d", c)
	}
}

func TestPlannerExportHasABucketPerPackAndATaskPerStep(t *testing.T) {
	s := buildoutServer(t, false)
	_, _ = call(t, s, "POST", "/api/tenants/t1/buildouts", `{"answers":{"platforms":["Windows"]}}`)
	_, _ = call(t, s, "POST", "/api/buildouts/1/steps/discover/complete", `{}`)
	code, out := call(t, s, "GET", "/api/buildouts/1/planner", "")
	if code != 200 {
		t.Fatal(code)
	}
	tasks := out["tasks"].([]any)
	buckets := out["buckets"].([]any)
	if len(tasks) < 5 || len(buckets) < 3 {
		t.Fatalf("%d tasks %d buckets", len(tasks), len(buckets))
	}
	first := tasks[0].(map[string]any)
	if first["done"] != true || first["bucket"] != "Discovery" {
		t.Fatalf("progress carries over: %v", first)
	}
	for _, tk := range tasks {
		m := tk.(map[string]any)
		if m["kind"] == "manual" && !strings.Contains(m["description"].(string), "A person does this step") {
			t.Fatalf("manual tasks say so: %v", m)
		}
	}
}

func TestObservedResultsOverTheAPIWithThePredictionBesideThem(t *testing.T) {
	statuses := `{"value":[{"deviceDisplayName":"LT-1","status":"compliant"},{"deviceDisplayName":"LT-2","status":"nonCompliant"}]}`
	s, _ := fleetServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/deviceStatuses") {
			_, _ = w.Write([]byte(statuses))
			return
		}
		healthyGraph(w, r)
	})
	if c, _ := fleetCall(s, "/api/tenants/t1/impact/observed", `{}`); c != 400 {
		t.Fatalf("%d", c)
	}
	code, out := fleetCall(s, "/api/tenants/t1/impact/observed", `{"policyId":"p1"}`)
	if code != 200 || out["percentCompliant"] != float64(50) || out["anyReported"] != true {
		t.Fatalf("%d %v", code, out)
	}
	code, out = fleetCall(s, "/api/tenants/nope/impact/observed", `{"policyId":"p1"}`)
	if code != 404 {
		t.Fatalf("%d", code)
	}
}

func TestDiscoveryIsTheBeforePicture(t *testing.T) {
	s, _ := fleetServer(t, healthyGraph)
	s.Impact = impact.SampleSource{}
	_, _, _ = s.Store.SaveVersion(store.Version{TenantID: "t1", Kind: "policies", ObjectID: "p1", Name: "Existing CA", Source: "manual", Body: []byte(`{"a":1}`)})
	_, _, _ = s.Store.SaveVersion(store.Version{TenantID: "t1", Kind: "device-configurations", ObjectID: "u1", Name: "Update ring", Source: "manual", Body: []byte(`{"a":2}`)})
	req := httptest.NewRequest("GET", "/api/tenants/t1/discovery", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	kinds := out["policiesByKind"].(map[string]any)
	if kinds["policies"] != float64(1) || kinds["device-configurations"] != float64(1) {
		t.Fatalf("%v", kinds)
	}
	win := out["devices"].(map[string]any)["byPlatform"].(map[string]any)["Windows"].(map[string]any)
	if win["devices"] != float64(42) || win["notSeen"] != float64(2) || win["oldestOS"] != "10.0.19044.5011" {
		t.Fatalf("%v", win)
	}
	notes := strings.Join(toStrings(out["notes"]), " ")
	if !strings.Contains(notes, "invented demo data") || !strings.Contains(notes, "No snapshot") {
		t.Fatalf("a demo says so, and a missing snapshot is explained: %s", notes)
	}
	if c, _ := fleetCall(s, "/api/tenants/nope/discovery", ``); c != 405 && c != 404 {
		t.Fatalf("%d", c)
	}
}

func toStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}
