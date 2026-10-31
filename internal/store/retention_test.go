package store

import (
	"testing"
	"time"
)

// Every test here owns its own temporary database, so a mistake in the delete
// can only ever hurt data the test created.
func seedVersions(t *testing.T, db *Store, obj string, ages []int) {
	t.Helper()
	now := time.Now().UTC()
	for i, days := range ages {
		_, err := db.db.Exec(`INSERT INTO object_versions (tenant_id, kind, object_id, name, version, captured_at, source, body, hash, deleted)
			VALUES ('t', 'policies', ?, 'n', ?, ?, 'scheduled', ?, ?, 0)`, obj, i+1, now.AddDate(0, 0, -days).Format(time.RFC3339), `{"v":`+string(rune('0'+i))+`}`, obj+string(rune('a'+i)))
		if err != nil {
			t.Fatal(err)
		}
	}
}

func count(t *testing.T, db *Store) int {
	var n int
	if err := db.db.QueryRow(`SELECT COUNT(*) FROM object_versions`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestOldVersionsGoButTheNewestOfEveryObjectNeverDoes(t *testing.T) {
	db := openDrift(t)
	seedVersions(t, db, "a", []int{400, 300, 200}) // all older than 90 days: the newest (v3) must survive
	seedVersions(t, db, "b", []int{400, 5})        // one old, one recent
	n, err := db.PruneVersions(90, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 || count(t, db) != 2 {
		t.Fatalf("removed %d, left %d", n, count(t, db))
	}
	for _, obj := range []string{"a", "b"} {
		h, _ := db.History("t", "policies", obj)
		if len(h) != 1 {
			t.Fatalf("object %s must keep its newest version: %d", obj, len(h))
		}
	}
}

func TestAVersionARunPointsAtIsKeptSoRevertLinksKeepWorking(t *testing.T) {
	db := openDrift(t)
	seedVersions(t, db, "a", []int{400, 300, 5})
	runID, _ := db.StartRun(Run{TenantID: "t", Action: "modify", Mode: "live", Actor: "x"})
	before := 1
	_ = db.AddRunItem(RunItem{RunID: runID, Kind: "policies", ObjectID: "a", Name: "n", Result: "updated", BeforeVer: &before})
	if _, err := db.PruneVersions(90, time.Now()); err != nil {
		t.Fatal(err)
	}
	h, _ := db.History("t", "policies", "a")
	got := map[int]bool{}
	for _, v := range h {
		got[v.Version] = true
	}
	if !got[1] || got[2] || !got[3] {
		t.Fatalf("version 1 is the run's before state and must stay, version 2 may go, the newest stays: %v", got)
	}
}

func TestARetentionBelowTheFloorIsRefusedAndDeletesNothing(t *testing.T) {
	db := openDrift(t)
	seedVersions(t, db, "a", []int{400, 300, 5})
	for _, days := range []int{0, 1, 29, -5} {
		if _, err := db.PruneVersions(days, time.Now()); err == nil {
			t.Fatalf("%d days must be refused", days)
		}
	}
	if count(t, db) != 3 {
		t.Fatal("a refused prune must delete nothing")
	}
	if n, _ := db.PruneVersions(MinRetentionDays, time.Now()); n != 2 {
		t.Fatalf("the floor itself is allowed: removed %d", n)
	}
}
