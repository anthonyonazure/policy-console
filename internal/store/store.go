// Package store persists tenants, every captured version of every policy
// object, and the record of what the console did. Version history is what
// makes "show me the setting five changes ago" and revert possible.
package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

const schema = `
CREATE TABLE IF NOT EXISTS tenants (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  added_at     TEXT NOT NULL,
  last_seen_at TEXT,
  status       TEXT NOT NULL DEFAULT 'pending',
  notes        TEXT NOT NULL DEFAULT ''
);

-- One row per captured state of one Graph object. version counts up per object.
CREATE TABLE IF NOT EXISTS object_versions (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id   TEXT NOT NULL,
  kind        TEXT NOT NULL,
  object_id   TEXT NOT NULL,
  name        TEXT NOT NULL,
  version     INTEGER NOT NULL,
  captured_at TEXT NOT NULL,
  source      TEXT NOT NULL,          -- scheduled | pre-change | post-change | manual
  run_id      INTEGER,
  body        TEXT NOT NULL,
  hash        TEXT NOT NULL,
  deleted     INTEGER NOT NULL DEFAULT 0,
  UNIQUE(tenant_id, kind, object_id, version)
);
CREATE INDEX IF NOT EXISTS idx_versions_object ON object_versions(tenant_id, kind, object_id, version DESC);
CREATE INDEX IF NOT EXISTS idx_versions_time ON object_versions(tenant_id, captured_at DESC);

CREATE TABLE IF NOT EXISTS runs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id   TEXT NOT NULL,
  action      TEXT NOT NULL,          -- deploy | modify | revert | snapshot | compare
  mode        TEXT NOT NULL,          -- preview | live
  actor       TEXT NOT NULL,
  started_at  TEXT NOT NULL,
  finished_at TEXT,
  summary     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_runs_tenant ON runs(tenant_id, started_at DESC);

CREATE TABLE IF NOT EXISTS run_items (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id      INTEGER NOT NULL,
  template_id TEXT NOT NULL DEFAULT '',
  kind        TEXT NOT NULL DEFAULT '',
  object_id   TEXT NOT NULL DEFAULT '',
  name        TEXT NOT NULL,
  result      TEXT NOT NULL,          -- created | exists | updated | reverted | failed | preview
  detail      TEXT NOT NULL DEFAULT '',
  before_ver  INTEGER,
  after_ver   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_run_items ON run_items(run_id);

-- Control frameworks fetched from their publishers, cached so a report does not
-- depend on GitHub being reachable at the moment someone presses the button.
CREATE TABLE IF NOT EXISTS benchmark_cache (
  source     TEXT PRIMARY KEY,
  version    TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  body       TEXT NOT NULL
);
`

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	if _, err := db.Exec(driftSchema); err != nil {
		return nil, fmt.Errorf("drift schema: %w", err)
	}
	if _, err := db.Exec(consentSchema); err != nil {
		return nil, fmt.Errorf("consent schema: %w", err)
	}
	if _, err := db.Exec(librarySchema); err != nil {
		return nil, fmt.Errorf("library schema: %w", err)
	}
	if _, err := db.Exec(reportSchema); err != nil {
		return nil, fmt.Errorf("report schema: %w", err)
	}
	if _, err := db.Exec(buildoutSchema); err != nil {
		return nil, fmt.Errorf("build out schema: %w", err)
	}
	if _, err := db.Exec(plannerSchema); err != nil {
		return nil, fmt.Errorf("planner schema: %w", err)
	}
	if _, err := db.Exec(tailorSchema); err != nil {
		return nil, fmt.Errorf("tailoring schema: %w", err)
	}
	if _, err := db.Exec(rolloutSchema); err != nil {
		return nil, fmt.Errorf("rollout schema: %w", err)
	}
	st := &Store{db: db}
	if err := st.migrateLifecycle(); err != nil {
		return nil, fmt.Errorf("lifecycle migration: %w", err)
	}
	return st, nil
}

func (s *Store) Close() error { return s.db.Close() }

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// ---- tenants ----

type Tenant struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	AddedAt    string `json:"addedAt"`
	LastSeenAt string `json:"lastSeenAt"`
	Status     string `json:"status"`
	Notes      string `json:"notes"`
}

func (s *Store) UpsertTenant(t Tenant) error {
	if t.AddedAt == "" {
		t.AddedAt = now()
	}
	_, err := s.db.Exec(`
		INSERT INTO tenants (id, name, added_at, last_seen_at, status, notes)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
		  name = excluded.name,
		  last_seen_at = COALESCE(excluded.last_seen_at, tenants.last_seen_at),
		  status = excluded.status,
		  notes = excluded.notes`,
		t.ID, t.Name, t.AddedAt, nullIfEmpty(t.LastSeenAt), t.Status, t.Notes)
	return err
}

func (s *Store) Tenants() ([]Tenant, error) {
	rows, err := s.db.Query(`SELECT id, name, added_at, COALESCE(last_seen_at,''), status, notes FROM tenants ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Tenant{}
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.AddedAt, &t.LastSeenAt, &t.Status, &t.Notes); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) Tenant(id string) (*Tenant, error) {
	var t Tenant
	err := s.db.QueryRow(`SELECT id, name, added_at, COALESCE(last_seen_at,''), status, notes FROM tenants WHERE id = ?`, id).
		Scan(&t.ID, &t.Name, &t.AddedAt, &t.LastSeenAt, &t.Status, &t.Notes)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &t, err
}

func (s *Store) DeleteTenant(id string) error {
	_, err := s.db.Exec(`DELETE FROM tenants WHERE id = ?`, id)
	return err
}

// ---- versions ----

type Version struct {
	ID         int64           `json:"id"`
	TenantID   string          `json:"tenantId"`
	Kind       string          `json:"kind"`
	ObjectID   string          `json:"objectId"`
	Name       string          `json:"name"`
	Version    int             `json:"version"`
	CapturedAt string          `json:"capturedAt"`
	Source     string          `json:"source"`
	RunID      *int64          `json:"runId,omitempty"`
	Hash       string          `json:"hash"`
	Deleted    bool            `json:"deleted"`
	Body       json.RawMessage `json:"body,omitempty"`
}

func Hash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// SaveVersion appends a new version unless the object is byte-identical to the
// version before it, so a nightly snapshot of an unchanged tenant costs one row
// per changed object rather than one row per object.
func (s *Store) SaveVersion(v Version) (int, bool, error) {
	v.Body = Redact(v.Body) // secrets never reach history; a changed secret still changes the hash

	var lastVer int
	var lastHash string
	err := s.db.QueryRow(
		`SELECT version, hash FROM object_versions
		 WHERE tenant_id = ? AND kind = ? AND object_id = ?
		 ORDER BY version DESC LIMIT 1`,
		v.TenantID, v.Kind, v.ObjectID).Scan(&lastVer, &lastHash)
	if err != nil && err != sql.ErrNoRows {
		return 0, false, err
	}
	h := Hash(v.Body)
	if err == nil && lastHash == h && !v.Deleted {
		return lastVer, false, nil
	}
	next := lastVer + 1
	del := 0
	if v.Deleted {
		del = 1
	}
	_, err = s.db.Exec(`
		INSERT INTO object_versions (tenant_id, kind, object_id, name, version, captured_at, source, run_id, body, hash, deleted)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		v.TenantID, v.Kind, v.ObjectID, v.Name, next, now(), v.Source, v.RunID, string(v.Body), h, del)
	return next, true, err
}

// History returns every captured version of one object, newest first.
func (s *Store) History(tenantID, kind, objectID string) ([]Version, error) {
	rows, err := s.db.Query(`
		SELECT id, name, version, captured_at, source, run_id, hash, deleted
		FROM object_versions
		WHERE tenant_id = ? AND kind = ? AND object_id = ?
		ORDER BY version DESC`, tenantID, kind, objectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Version{}
	for rows.Next() {
		v := Version{TenantID: tenantID, Kind: kind, ObjectID: objectID}
		var del int
		if err := rows.Scan(&v.ID, &v.Name, &v.Version, &v.CapturedAt, &v.Source, &v.RunID, &v.Hash, &del); err != nil {
			return nil, err
		}
		v.Deleted = del == 1
		out = append(out, v)
	}
	return out, rows.Err()
}

// VersionBody returns one stored version. version 0 means "the latest".
func (s *Store) VersionBody(tenantID, kind, objectID string, version int) (*Version, error) {
	q := `SELECT id, name, version, captured_at, source, run_id, hash, deleted, body
	      FROM object_versions WHERE tenant_id = ? AND kind = ? AND object_id = ?`
	args := []any{tenantID, kind, objectID}
	if version > 0 {
		q += ` AND version = ?`
		args = append(args, version)
	} else {
		q += ` ORDER BY version DESC LIMIT 1`
	}
	v := Version{TenantID: tenantID, Kind: kind, ObjectID: objectID}
	var del int
	var body string
	err := s.db.QueryRow(q, args...).Scan(&v.ID, &v.Name, &v.Version, &v.CapturedAt, &v.Source, &v.RunID, &v.Hash, &del, &body)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	v.Deleted = del == 1
	v.Body = json.RawMessage(body)
	return &v, nil
}

// LatestObjects returns the newest version of every object in a tenant.
func (s *Store) LatestObjects(tenantID string) ([]Version, error) {
	rows, err := s.db.Query(`
		SELECT ov.id, ov.kind, ov.object_id, ov.name, ov.version, ov.captured_at, ov.source, ov.hash, ov.deleted, ov.body
		FROM object_versions ov
		JOIN (SELECT kind, object_id, MAX(version) AS v FROM object_versions WHERE tenant_id = ? GROUP BY kind, object_id) m
		  ON m.kind = ov.kind AND m.object_id = ov.object_id AND m.v = ov.version
		WHERE ov.tenant_id = ?
		ORDER BY ov.kind, ov.name`, tenantID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Version{}
	for rows.Next() {
		v := Version{TenantID: tenantID}
		var del int
		var body string
		if err := rows.Scan(&v.ID, &v.Kind, &v.ObjectID, &v.Name, &v.Version, &v.CapturedAt, &v.Source, &v.Hash, &del, &body); err != nil {
			return nil, err
		}
		v.Deleted = del == 1
		v.Body = json.RawMessage(body)
		out = append(out, v)
	}
	return out, rows.Err()
}

// ---- runs ----

type Run struct {
	ID         int64     `json:"id"`
	TenantID   string    `json:"tenantId"`
	Action     string    `json:"action"`
	Mode       string    `json:"mode"`
	Actor      string    `json:"actor"`
	StartedAt  string    `json:"startedAt"`
	FinishedAt string    `json:"finishedAt"`
	Summary    string    `json:"summary"`
	Items      []RunItem `json:"items,omitempty"`
}

type RunItem struct {
	ID         int64  `json:"id"`
	RunID      int64  `json:"runId"`
	TemplateID string `json:"templateId"`
	Kind       string `json:"kind"`
	ObjectID   string `json:"objectId"`
	Name       string `json:"name"`
	Result     string `json:"result"`
	Detail     string `json:"detail"`
	BeforeVer  *int   `json:"beforeVersion,omitempty"`
	AfterVer   *int   `json:"afterVersion,omitempty"`
}

func (s *Store) StartRun(r Run) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO runs (tenant_id, action, mode, actor, started_at) VALUES (?, ?, ?, ?, ?)`,
		r.TenantID, r.Action, r.Mode, r.Actor, now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) AddRunItem(it RunItem) error {
	_, err := s.db.Exec(`
		INSERT INTO run_items (run_id, template_id, kind, object_id, name, result, detail, before_ver, after_ver)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		it.RunID, it.TemplateID, it.Kind, it.ObjectID, it.Name, it.Result, it.Detail, it.BeforeVer, it.AfterVer)
	return err
}

func (s *Store) FinishRun(id int64, summary string) error {
	_, err := s.db.Exec(`UPDATE runs SET finished_at = ?, summary = ? WHERE id = ?`, now(), summary, id)
	return err
}

func (s *Store) Runs(tenantID string, limit int) ([]Run, error) {
	if limit <= 0 {
		limit = 50
	}
	q := `SELECT id, tenant_id, action, mode, actor, started_at, COALESCE(finished_at,''), summary FROM runs`
	args := []any{}
	if tenantID != "" {
		q += ` WHERE tenant_id = ?`
		args = append(args, tenantID)
	}
	q += ` ORDER BY started_at DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Run{}
	for rows.Next() {
		var r Run
		if err := rows.Scan(&r.ID, &r.TenantID, &r.Action, &r.Mode, &r.Actor, &r.StartedAt, &r.FinishedAt, &r.Summary); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) RunItems(runID int64) ([]RunItem, error) {
	rows, err := s.db.Query(`
		SELECT id, run_id, template_id, kind, object_id, name, result, detail, before_ver, after_ver
		FROM run_items WHERE run_id = ? ORDER BY id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RunItem{}
	for rows.Next() {
		var it RunItem
		if err := rows.Scan(&it.ID, &it.RunID, &it.TemplateID, &it.Kind, &it.ObjectID, &it.Name, &it.Result, &it.Detail, &it.BeforeVer, &it.AfterVer); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ---- benchmark cache ----

func (s *Store) SaveBenchmark(source, version string, body []byte) error {
	_, err := s.db.Exec(`
		INSERT INTO benchmark_cache (source, version, fetched_at, body) VALUES (?, ?, ?, ?)
		ON CONFLICT(source) DO UPDATE SET version = excluded.version,
		  fetched_at = excluded.fetched_at, body = excluded.body`,
		source, version, now(), string(body))
	return err
}

// Benchmarks returns every cached framework catalog, keyed by source name.
func (s *Store) Benchmarks() (map[string][]byte, error) {
	rows, err := s.db.Query(`SELECT source, body FROM benchmark_cache`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]byte{}
	for rows.Next() {
		var source, body string
		if err := rows.Scan(&source, &body); err != nil {
			return nil, err
		}
		out[source] = []byte(body)
	}
	return out, rows.Err()
}
