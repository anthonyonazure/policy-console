package store

import (
	"path/filepath"
	"testing"
)

func TestBackupIsConsistentAndRestorable(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "live.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, id := range []string{"a", "b", "c"} {
		if err := s.UpsertTenant(Tenant{ID: id, Name: id, Status: "connected"}); err != nil {
			t.Fatal(err)
		}
	}
	path, err := s.Backup(filepath.Join(dir, "backups"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Counts(path)
	if err != nil {
		t.Fatal(err)
	}
	if got["tenants"] != 3 {
		t.Fatalf("backup has %d tenants, want 3 (%v)", got["tenants"], got)
	}
	if _, err := Counts(filepath.Join(dir, "missing.db")); err == nil {
		t.Fatal("missing file should error")
	}
}
