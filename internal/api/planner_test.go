package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// recorder answers just enough of Planner to follow what the console does.
type recorder struct {
	mu    sync.Mutex
	calls []string
	n     int
	pct   map[string]float64
}

func (r *recorder) Request(_ context.Context, method, uri string, body []byte, _ map[string]string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, method+" "+uri+" "+string(body))
	r.n++
	id := fmt.Sprintf("id%d", r.n)
	var in map[string]any
	_ = json.Unmarshal(body, &in)
	switch {
	case method == "GET" && strings.HasSuffix(uri, "/buckets"):
		return []byte(`{"value":[]}`), nil
	case method == "GET" && strings.HasSuffix(uri, "/details"):
		return []byte(`{"description":"","@odata.etag":"d"}`), nil
	case method == "GET" && strings.Contains(uri, "/tasks/"):
		t := strings.TrimPrefix(uri, "/v1.0/planner/tasks/")
		b, _ := json.Marshal(map[string]any{"title": "x", "percentComplete": r.pct[t], "@odata.etag": "e"})
		return b, nil
	case method == "POST" && strings.HasSuffix(uri, "/tasks"):
		return []byte(`{"id":"` + id + `"}`), nil
	case method == "PATCH" && strings.Contains(uri, "/tasks/") && !strings.HasSuffix(uri, "/details"):
		if v, ok := in["percentComplete"].(float64); ok {
			r.pct[strings.TrimPrefix(uri, "/v1.0/planner/tasks/")] = v
		}
		return []byte(`{}`), nil
	case method == "GET":
		return []byte(`{"id":"P"}`), nil
	}
	return []byte(`{"id":"` + id + `"}`), nil
}

func (r *recorder) count(sub string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		if strings.Contains(c, sub) {
			n++
		}
	}
	return n
}

func newBuildout(t *testing.T, s *Server) {
	t.Helper()
	if code, out := call(t, s, "POST", "/api/tenants/t1/buildouts", `{"answers":{"platforms":["Windows"]}}`); code != 201 {
		t.Fatalf("%d %v", code, out)
	}
}

func TestPlannerNotConfigured(t *testing.T) {
	s := buildoutServer(t, false)
	newBuildout(t, s)
	if code, _ := call(t, s, "POST", "/api/buildouts/1/planner/sync", `{}`); code != 503 {
		t.Fatalf("want 503, got %d", code)
	}
	if _, out := call(t, s, "GET", "/api/planner/status", ``); out["configured"] != false {
		t.Fatalf("%v", out)
	}
}

func TestPlannerPostThenKeepUpToDate(t *testing.T) {
	s := buildoutServer(t, false)
	s.Cfg.PlannerGroupID = "g1"
	rec := &recorder{pct: map[string]float64{}}
	s.Planner = rec
	newBuildout(t, s)

	// A step change before anything was posted must not post by itself.
	call(t, s, "POST", "/api/buildouts/1/steps/discover/complete", `{"note":"ok"}`)
	if len(rec.calls) != 0 {
		t.Fatalf("posted without being asked: %v", rec.calls)
	}

	code, pv := call(t, s, "POST", "/api/buildouts/1/planner/preview", `{}`)
	if code != 200 || pv["posted"] != false || len(rec.calls) != 0 {
		t.Fatalf("preview must not call Planner: %d %v %v", code, pv, rec.calls)
	}

	code, out := call(t, s, "POST", "/api/buildouts/1/planner/sync", `{}`)
	if code != 200 || out["created"].(float64) < 2 {
		t.Fatalf("%d %v", code, out)
	}
	if rec.count("POST /v1.0/planner/plans {") != 1 {
		t.Fatalf("one plan expected: %v", rec.calls)
	}
	if !strings.Contains(strings.Join(rec.calls, "\n"), "Console status: done") {
		t.Fatal("the finished step should say so in its notes")
	}

	// Posting again changes nothing.
	before := rec.count("POST ")
	if _, out := call(t, s, "POST", "/api/buildouts/1/planner/sync", `{}`); out["created"].(float64) != 0 {
		t.Fatalf("%v", out)
	}
	if rec.count("POST ") != before {
		t.Fatal("second sync created things")
	}

	// A new step change now flows to Planner on its own.
	patches := rec.count("PATCH ")
	_, pl := call(t, s, "GET", "/api/buildouts/1", ``)
	_ = pl
	call(t, s, "POST", "/api/buildouts/1/steps/compliance/skip", `{"reason":"not needed"}`)
	if rec.count("PATCH ") == patches {
		t.Fatalf("a changed step should update Planner: %v", rec.calls)
	}
}

func TestPlannerRefusesInReadOnlyMode(t *testing.T) {
	s := buildoutServer(t, true)
	s.Cfg.PlannerGroupID = "g1"
	s.Planner = &recorder{pct: map[string]float64{}}
	newBuildout(t, s)
	if code, _ := call(t, s, "POST", "/api/buildouts/1/planner/sync", `{}`); code != 403 {
		t.Fatalf("want 403, got %d", code)
	}
}
