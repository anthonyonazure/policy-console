package planner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/anthonyonazure/policy-console/internal/graph"
)

// fake is a tiny stand-in for the Planner part of Graph.
type fake struct {
	plans, buckets, tasks map[string]map[string]any
	details               map[string]map[string]any
	n                     int
	calls                 []string
	failDetailsOnce       bool
	staleOnce             bool
}

func newFake() *fake {
	return &fake{plans: map[string]map[string]any{}, buckets: map[string]map[string]any{}, tasks: map[string]map[string]any{}, details: map[string]map[string]any{}}
}

func (f *fake) id(p string) string { f.n++; return fmt.Sprintf("%s%d", p, f.n) }

func (f *fake) Request(_ context.Context, method, uri string, body []byte, hdr map[string]string) ([]byte, error) {
	f.calls = append(f.calls, method+" "+uri)
	var in map[string]any
	_ = json.Unmarshal(body, &in)
	out := func(m map[string]any) ([]byte, error) { return json.Marshal(m) }
	notFound := &graph.APIError{Status: 404, Body: "gone"}
	switch {
	case method == "POST" && uri == "/v1.0/planner/plans":
		id := f.id("plan")
		f.plans[id] = map[string]any{"id": id, "title": in["title"]}
		return out(f.plans[id])
	case method == "GET" && strings.HasPrefix(uri, "/v1.0/planner/plans/") && strings.HasSuffix(uri, "/buckets"):
		var vals []any
		for _, b := range f.buckets {
			vals = append(vals, b)
		}
		return json.Marshal(map[string]any{"value": vals})
	case method == "GET" && strings.HasPrefix(uri, "/v1.0/planner/plans/"):
		id := strings.TrimPrefix(uri, "/v1.0/planner/plans/")
		if p, ok := f.plans[id]; ok {
			return out(p)
		}
		return nil, notFound
	case method == "POST" && uri == "/v1.0/planner/buckets":
		id := f.id("bucket")
		f.buckets[id] = map[string]any{"id": id, "name": in["name"]}
		return out(f.buckets[id])
	case method == "POST" && uri == "/v1.0/planner/tasks":
		id := f.id("task")
		t := map[string]any{"id": id, "title": in["title"], "bucketId": in["bucketId"], "percentComplete": 0.0, "@odata.etag": "t1"}
		if v, ok := in["percentComplete"]; ok {
			t["percentComplete"] = v
		}
		f.tasks[id] = t
		f.details[id] = map[string]any{"description": "", "@odata.etag": "d1"}
		return out(t)
	case strings.HasSuffix(uri, "/details"):
		id := strings.TrimSuffix(strings.TrimPrefix(uri, "/v1.0/planner/tasks/"), "/details")
		d, ok := f.details[id]
		if !ok {
			return nil, notFound
		}
		if method == "GET" {
			return out(d)
		}
		if f.failDetailsOnce {
			f.failDetailsOnce = false
			return nil, &graph.APIError{Status: 500, Body: "boom"}
		}
		if hdr["If-Match"] != d["@odata.etag"] {
			return nil, &graph.APIError{Status: 412}
		}
		d["description"] = in["description"]
		d["@odata.etag"] = d["@odata.etag"].(string) + "x"
		return out(d)
	case strings.HasPrefix(uri, "/v1.0/planner/tasks/"):
		id := strings.TrimPrefix(uri, "/v1.0/planner/tasks/")
		t, ok := f.tasks[id]
		if !ok {
			return nil, notFound
		}
		if method == "GET" {
			c := map[string]any{}
			for k, v := range t {
				c[k] = v
			}
			if f.staleOnce { // the task changes right after we read it
				f.staleOnce = false
				t["@odata.etag"] = "moved"
			}
			return out(c)
		}
		if hdr["If-Match"] != t["@odata.etag"] {
			return nil, &graph.APIError{Status: 412}
		}
		for k, v := range in {
			t[k] = v
		}
		return out(t)
	}
	return nil, fmt.Errorf("unexpected %s %s", method, uri)
}

type mem struct {
	plan  string
	links map[string]Link
}

func (m *mem) Plan() string                { return m.plan }
func (m *mem) SetPlan(id string) error     { m.plan = id; return nil }
func (m *mem) Links() map[string]Link      { return m.links }
func (m *mem) Save(s string, l Link) error { m.links[s] = l; return nil }

func spec(done bool) Spec {
	return Spec{Title: "Intune build out: Acme", Tasks: []Task{
		{StepID: "a", Title: "Baseline", Bucket: "Core", Description: "why a"},
		{StepID: "b", Title: "Devices", Bucket: "Devices", Description: "why b", Done: done},
	}}
}

func count(f *fake, prefix string) int {
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func TestFirstSyncCreatesPlanBucketsAndTasks(t *testing.T) {
	f, st := newFake(), &mem{links: map[string]Link{}}
	s := &Syncer{API: f, GroupID: "g1"}
	res, err := s.Sync(context.Background(), spec(false), st)
	if err != nil || res.Created != 2 || len(res.Failed) != 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if len(f.plans) != 1 || len(f.buckets) != 2 || len(f.tasks) != 2 {
		t.Fatalf("plans=%d buckets=%d tasks=%d", len(f.plans), len(f.buckets), len(f.tasks))
	}
	if st.plan == "" || len(st.links) != 2 {
		t.Fatalf("state not remembered: %+v", st)
	}
}

func TestSecondSyncWithNoChangeMakesNoWrites(t *testing.T) {
	f, st := newFake(), &mem{links: map[string]Link{}}
	s := &Syncer{API: f, GroupID: "g1"}
	_, _ = s.Sync(context.Background(), spec(false), st)
	f.calls = nil
	res, err := s.Sync(context.Background(), spec(false), st)
	if err != nil || res.Unchanged != 2 || res.Created+res.Updated != 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	for _, c := range f.calls {
		if !strings.HasPrefix(c, "GET") {
			t.Fatalf("unexpected write: %s", c)
		}
	}
}

func TestFinishedStepMarksTaskComplete(t *testing.T) {
	f, st := newFake(), &mem{links: map[string]Link{}}
	s := &Syncer{API: f, GroupID: "g1"}
	_, _ = s.Sync(context.Background(), spec(false), st)
	res, err := s.Sync(context.Background(), spec(true), st)
	if err != nil || res.Updated != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if f.tasks[st.links["b"].TaskID]["percentComplete"] != 100 && f.tasks[st.links["b"].TaskID]["percentComplete"] != 100.0 {
		t.Fatalf("task b not complete: %v", f.tasks[st.links["b"].TaskID])
	}
}

func TestPersonFinishedTaskIsNeverReopened(t *testing.T) {
	f, st := newFake(), &mem{links: map[string]Link{}}
	s := &Syncer{API: f, GroupID: "g1"}
	_, _ = s.Sync(context.Background(), spec(false), st)
	f.tasks[st.links["a"].TaskID]["percentComplete"] = 100.0 // a person ticked it in Planner
	sp := spec(false)
	sp.Tasks[0].Description = "why a, edited"
	res, err := s.Sync(context.Background(), sp, st)
	if err != nil || len(res.CompletedInPlanner) != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if f.tasks[st.links["a"].TaskID]["percentComplete"] != 100.0 {
		t.Fatal("task was reopened")
	}
}

func TestDeletedTaskIsNotRecreated(t *testing.T) {
	f, st := newFake(), &mem{links: map[string]Link{}}
	s := &Syncer{API: f, GroupID: "g1"}
	_, _ = s.Sync(context.Background(), spec(false), st)
	delete(f.tasks, st.links["a"].TaskID)
	delete(f.details, st.links["a"].TaskID)
	before := len(f.tasks)
	sp := spec(false)
	sp.Tasks[0].Title = "Baseline v2"
	res, _ := s.Sync(context.Background(), sp, st)
	if len(res.RemovedInPlanner) != 1 || len(f.tasks) != before {
		t.Fatalf("res=%+v tasks=%d", res, len(f.tasks))
	}
}

func TestStaleEtagIsRetried(t *testing.T) {
	f, st := newFake(), &mem{links: map[string]Link{}}
	s := &Syncer{API: f, GroupID: "g1"}
	_, _ = s.Sync(context.Background(), spec(false), st)
	f.staleOnce = true
	res, err := s.Sync(context.Background(), spec(true), st)
	if err != nil || len(res.Failed) != 0 || res.Updated != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestHalfMadeTaskIsFinishedNotDuplicated(t *testing.T) {
	f, st := newFake(), &mem{links: map[string]Link{}}
	s := &Syncer{API: f, GroupID: "g1"}
	f.failDetailsOnce = true
	res, _ := s.Sync(context.Background(), spec(false), st)
	if len(res.Failed) != 1 {
		t.Fatalf("expected one failure, got %+v", res)
	}
	res, err := s.Sync(context.Background(), spec(false), st)
	if err != nil || len(res.Failed) != 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if len(f.tasks) != 2 {
		t.Fatalf("duplicated: %d tasks", len(f.tasks))
	}
	if f.details[st.links["a"].TaskID]["description"] != "why a" {
		t.Fatal("notes never filled in")
	}
}

func TestExistingPlanModeReusesBucketsAndNeverCreatesAPlan(t *testing.T) {
	f, st := newFake(), &mem{links: map[string]Link{}}
	f.plans["P"] = map[string]any{"id": "P"}
	f.buckets["B"] = map[string]any{"id": "B", "name": "Core"}
	s := &Syncer{API: f, PlanID: "P"}
	if _, err := s.Sync(context.Background(), spec(false), st); err != nil {
		t.Fatal(err)
	}
	if count(f, "POST /v1.0/planner/plans") != 0 || len(f.buckets) != 2 || st.plan != "P" {
		t.Fatalf("calls=%v buckets=%d", f.calls, len(f.buckets))
	}
}

func TestNotConfigured(t *testing.T) {
	_, err := (&Syncer{API: newFake()}).Sync(context.Background(), spec(false), &mem{links: map[string]Link{}})
	if err != ErrNotConfigured {
		t.Fatalf("err=%v", err)
	}
}

func TestPermissionRefusalSaysWhatToFix(t *testing.T) {
	s := &Syncer{API: refuse{}, GroupID: "g"}
	_, err := s.Sync(context.Background(), spec(false), &mem{links: map[string]Link{}})
	if err == nil || !strings.Contains(err.Error(), "Tasks.ReadWrite.All") {
		t.Fatalf("err=%v", err)
	}
}

type refuse struct{}

func (refuse) Request(context.Context, string, string, []byte, map[string]string) ([]byte, error) {
	return nil, &graph.APIError{Status: http.StatusForbidden, Body: "no"}
}

func TestPreviewCounts(t *testing.T) {
	f, st := newFake(), &mem{links: map[string]Link{}}
	s := &Syncer{API: f, GroupID: "g1"}
	if p := Plan(spec(false), st); p.WouldPost != 2 || p.Posted {
		t.Fatalf("%+v", p)
	}
	_, _ = s.Sync(context.Background(), spec(false), st)
	if p := Plan(spec(true), st); p.WouldEdit != 1 || p.Unchanged != 1 || !p.Posted {
		t.Fatalf("%+v", p)
	}
}
