package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Backup writes a consistent, self-contained snapshot of the database into dir
// using VACUUM INTO, which is safe while the console is running and in WAL mode.
// It returns the path of the new file. An existing file is never overwritten.
func (s *Store) Backup(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	dest := filepath.Join(dir, "policy-console-"+time.Now().UTC().Format("20060102T150405Z")+".db")
	if _, err := os.Stat(dest); err == nil {
		return "", fmt.Errorf("backup %s already exists", dest)
	}
	if _, err := s.db.Exec("VACUUM INTO ?", dest); err != nil {
		return "", fmt.Errorf("backup: %w", err)
	}
	return dest, nil
}

// Counts opens a database file read-only, checks its integrity and returns the
// row count of every table. It is what the restore drill compares.
func Counts(path string) (map[string]int, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var check string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&check); err != nil {
		return nil, err
	}
	if check != "ok" {
		return nil, fmt.Errorf("integrity check failed: %s", check)
	}
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
	if err != nil {
		return nil, err
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return nil, err
		}
		tables = append(tables, n)
	}
	rows.Close()
	out := map[string]int{}
	for _, t := range tables {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM "` + strings.ReplaceAll(t, `"`, `""`) + `"`).Scan(&n); err != nil {
			return nil, err
		}
		out[t] = n
	}
	return out, nil
}

// FormatCounts renders counts as sorted "table=n" lines.
func FormatCounts(c map[string]int) string {
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%d\n", k, c[k])
	}
	return b.String()
}
