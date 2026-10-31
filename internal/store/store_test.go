package store

import (
	"path/filepath"
	"testing"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// An unchanged object must not create a new version on every scheduled snapshot,
// or a nightly capture of fifty tenants would bury the real changes.
func TestIdenticalCaptureDoesNotVersion(t *testing.T) {
	s := open(t)
	v := Version{TenantID: "t1", Kind: "policies", ObjectID: "o1", Name: "P", Source: "scheduled", Body: []byte(`{"a":1}`)}
	if n, changed, _ := s.SaveVersion(v); n != 1 || !changed {
		t.Fatalf("first capture should be version 1, got %d changed=%v", n, changed)
	}
	if n, changed, _ := s.SaveVersion(v); n != 1 || changed {
		t.Fatalf("identical capture should not version, got %d changed=%v", n, changed)
	}
	v.Body = []byte(`{"a":2}`)
	if n, changed, _ := s.SaveVersion(v); n != 2 || !changed {
		t.Fatalf("changed capture should be version 2, got %d changed=%v", n, changed)
	}
}

func TestHistoryWalksBackFiveChanges(t *testing.T) {
	s := open(t)
	for i := 0; i < 6; i++ {
		_, _, err := s.SaveVersion(Version{TenantID: "t1", Kind: "policies", ObjectID: "o1", Name: "P",
			Source: "manual", Body: []byte(`{"n":` + string(rune('0'+i)) + `}`)})
		if err != nil {
			t.Fatal(err)
		}
	}
	h, err := s.History("t1", "policies", "o1")
	if err != nil || len(h) != 6 {
		t.Fatalf("expected 6 versions, got %d (%v)", len(h), err)
	}
	if h[0].Version != 6 {
		t.Fatalf("history should be newest first, got %d", h[0].Version)
	}
	five := h[5]
	body, err := s.VersionBody("t1", "policies", "o1", five.Version)
	if err != nil || body == nil {
		t.Fatalf("could not read the oldest version: %v", err)
	}
}

func TestRunsRecordWhoDidWhat(t *testing.T) {
	s := open(t)
	id, err := s.StartRun(Run{TenantID: "t1", Action: "deploy", Mode: "live", Actor: "tech@house"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddRunItem(RunItem{RunID: id, Name: "P", Result: "created"}); err != nil {
		t.Fatal(err)
	}
	_ = s.FinishRun(id, "1 created")
	runs, _ := s.Runs("t1", 10)
	if len(runs) != 1 || runs[0].Actor != "tech@house" {
		t.Fatalf("run not recorded: %+v", runs)
	}
	items, _ := s.RunItems(id)
	if len(items) != 1 {
		t.Fatalf("run items missing: %+v", items)
	}
}
