package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestAFindingMovesThroughNewAcknowledgedSnoozedAndBack(t *testing.T) {
	db := openDrift(t)
	t0 := time.Now()
	_, _ = db.ApplyFindings("t", []Finding{f("a", "missing", "critical")}, nil, t0)
	o, _ := db.OpenFindings("t")
	id := o[0].ID
	if o[0].State != StateNew {
		t.Fatal(o[0].State)
	}
	if err := db.Acknowledge(id, "", "x", t0); err == nil {
		t.Fatal("an acknowledgement must name the person")
	}
	if err := db.Acknowledge(id, "anthony", "client knows", t0); err != nil {
		t.Fatal(err)
	}
	o, _ = db.OpenFindings("t")
	if o[0].State != StateAcknowledged || o[0].AckedBy != "anthony" || o[0].AckNote != "client knows" {
		t.Fatalf("%+v", o[0])
	}
	if err := db.Snooze(id, "anthony", "", t0.Add(-time.Hour), t0); err == nil {
		t.Fatal("a snooze in the past does nothing and must be refused")
	}
	if err := db.Snooze(id, "anthony", "until patch day", t0.Add(48*time.Hour), t0); err != nil {
		t.Fatal(err)
	}
	o, _ = db.OpenFindings("t")
	if o[0].State != StateSnoozed {
		t.Fatalf("%+v", o[0])
	}
	// The snooze runs out: the finding is new again without anyone doing anything.
	if got := o[0].StateAt(t0.Add(72 * time.Hour)); got != StateNew {
		t.Fatalf("an expired snooze means new again: %s", got)
	}
	if err := db.Reopen(id); err != nil {
		t.Fatal(err)
	}
	o, _ = db.OpenFindings("t")
	if o[0].State != StateNew || o[0].AckedBy != "" {
		t.Fatalf("%+v", o[0])
	}
	if err := db.Acknowledge(9999, "a", "", t0); err != ErrNoSuchFinding {
		t.Fatalf("%v", err)
	}
}

func TestARecurrenceIsNewAgainEvenIfItWasAcknowledgedBefore(t *testing.T) {
	db := openDrift(t)
	t0 := time.Now()
	_, _ = db.ApplyFindings("t", []Finding{f("a", "missing", "critical")}, nil, t0)
	o, _ := db.OpenFindings("t")
	_ = db.Acknowledge(o[0].ID, "anthony", "", t0)
	_, _ = db.ApplyFindings("t", nil, nil, t0.Add(time.Hour))                                        // fixed
	_, _ = db.ApplyFindings("t", []Finding{f("a", "missing", "critical")}, nil, t0.Add(2*time.Hour)) // broke again
	o, _ = db.OpenFindings("t")
	if o[0].State != StateNew {
		t.Fatalf("it broke again, so someone must look again: %+v", o[0])
	}
}

func TestAnOlderDatabaseIsUpgradedInPlace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// A findings table as it was before the lifecycle columns existed.
	if _, err := raw.Exec(`CREATE TABLE drift_findings (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, template_id TEXT NOT NULL,
		class TEXT NOT NULL, severity TEXT NOT NULL, name TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', first_seen TEXT NOT NULL,
		last_seen TEXT NOT NULL, resolved_at TEXT, notified_at TEXT, UNIQUE(tenant_id, template_id, class));
		INSERT INTO drift_findings (tenant_id, template_id, class, severity, name, first_seen, last_seen) VALUES ('t','a','missing','critical','A','x','x')`); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	db, err := Open(path)
	if err != nil {
		t.Fatalf("an older database must open: %v", err)
	}
	defer db.Close()
	o, err := db.OpenFindings("t")
	if err != nil || len(o) != 1 || o[0].State != StateNew {
		t.Fatalf("%v %+v", err, o)
	}
	// Opening it a second time must not fail on the columns that now exist.
	db2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	db2.Close()
}
