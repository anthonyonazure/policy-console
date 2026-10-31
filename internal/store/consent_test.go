package store

import (
	"testing"
	"time"
)

func TestConsentsReflectOnlyWhatWasLastSeen(t *testing.T) {
	db := openDrift(t)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	all := []string{"A", "B"}
	_ = db.SaveConsents("t", "write", map[string]bool{"A": true, "B": true}, all, t0)
	got, _ := db.Consents("t", "write")
	if len(got) != 2 {
		t.Fatal(got)
	}
	// B was revoked in the client's portal; the next read-back must notice.
	_ = db.SaveConsents("t", "write", map[string]bool{"A": true}, all, t0.Add(time.Hour))
	got, _ = db.Consents("t", "write")
	if len(got) != 1 || got["A"] == "" {
		t.Fatalf("a revoked permission must disappear: %v", got)
	}
	if other, _ := db.Consents("t", "read"); len(other) != 0 {
		t.Fatal("registrations are separate")
	}
}
