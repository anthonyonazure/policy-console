package store

import (
	"path/filepath"
	"testing"
	"time"
)

func openDrift(t *testing.T) *Store {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func f(id, class, sev string) Finding {
	return Finding{TemplateID: id, Class: class, Severity: sev, Name: id}
}

func TestFindingLifecycle(t *testing.T) {
	db := openDrift(t)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

	c, err := db.ApplyFindings("t", []Finding{f("a", "missing", "critical"), f("b", "changed", "warning")}, nil, t0)
	if err != nil || len(c.Opened) != 2 || len(c.Resolved) != 0 {
		t.Fatalf("first check: %+v %v", c, err)
	}

	// Same findings again: nothing new, nothing resolved.
	c, _ = db.ApplyFindings("t", []Finding{f("a", "missing", "critical"), f("b", "changed", "warning")}, nil, t0.Add(24*time.Hour))
	if len(c.Opened) != 0 || len(c.Resolved) != 0 {
		t.Fatalf("repeat check must be quiet: %+v", c)
	}

	// b fixed.
	c, _ = db.ApplyFindings("t", []Finding{f("a", "missing", "critical")}, nil, t0.Add(48*time.Hour))
	if len(c.Resolved) != 1 || c.Resolved[0].TemplateID != "b" {
		t.Fatalf("b should resolve: %+v", c)
	}
	open, _ := db.OpenFindings("t")
	if len(open) != 1 || open[0].TemplateID != "a" {
		t.Fatalf("open = %+v", open)
	}

	// b comes back: it is new again, and its notification state is cleared.
	_ = db.MarkNotified([]int64{open[0].ID}, t0)
	c, _ = db.ApplyFindings("t", []Finding{f("a", "missing", "critical"), f("b", "changed", "warning")}, nil, t0.Add(72*time.Hour))
	if len(c.Opened) != 1 || c.Opened[0].TemplateID != "b" {
		t.Fatalf("a recurrence must be announced again: %+v", c)
	}
}

func TestFindingsAreScopedPerTenant(t *testing.T) {
	db := openDrift(t)
	now := time.Now()
	_, _ = db.ApplyFindings("one", []Finding{f("a", "missing", "critical")}, nil, now)
	c, _ := db.ApplyFindings("two", nil, nil, now)
	if len(c.Resolved) != 0 {
		t.Fatal("checking tenant two must not resolve tenant one's findings")
	}
	if o, _ := db.OpenFindings("one"); len(o) != 1 {
		t.Fatalf("tenant one lost its finding: %+v", o)
	}
}

func TestCriticalSortsFirst(t *testing.T) {
	db := openDrift(t)
	_, _ = db.ApplyFindings("t", []Finding{f("a", "extra", "info"), f("b", "missing", "critical"), f("c", "changed", "warning")}, nil, time.Now())
	o, _ := db.OpenFindings("t")
	if o[0].Severity != "critical" || o[2].Severity != "info" {
		t.Fatalf("order: %+v", o)
	}
}

func TestTokensAndKV(t *testing.T) {
	db := openDrift(t)
	if m, err := db.Tokens("t"); err != nil || len(m) != 0 {
		t.Fatalf("empty tokens: %v %v", m, err)
	}
	_ = db.SetTokens("t", map[string]string{"A": "1"})
	_ = db.SetTokens("t", map[string]string{"B": "2"})
	m, _ := db.Tokens("t")
	if len(m) != 1 || m["B"] != "2" {
		t.Fatalf("tokens must be replaced, not merged: %v", m)
	}
	_ = db.SetKV("k", "v1")
	_ = db.SetKV("k", "v2")
	if v, _ := db.KV("k"); v != "v2" {
		t.Fatal(v)
	}
}

func TestExceptionActive(t *testing.T) {
	now := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	if !(Exception{}).Active(now) {
		t.Error("no expiry means active")
	}
	if (Exception{ExpiresAt: "2026-10-26T00:00:00Z"}).Active(now) {
		t.Error("past expiry means inactive")
	}
	if !(Exception{ExpiresAt: "2026-10-28T00:00:00Z"}).Active(now) {
		t.Error("future expiry means active")
	}
}
