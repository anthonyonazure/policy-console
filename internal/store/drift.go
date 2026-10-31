package store

import (
	"database/sql"
	"encoding/json"
	"time"
)

// driftSchema holds what scheduled drift checking needs to remember: the
// per-client values that fill template placeholders, the exceptions someone
// approved, and every finding with when it first appeared and when it was told.
const driftSchema = `
CREATE TABLE IF NOT EXISTS tenant_tokens (
  tenant_id  TEXT PRIMARY KEY,
  tokens     TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS drift_exceptions (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id   TEXT NOT NULL,
  template_id TEXT NOT NULL,          -- a template id, or "extra:<kind>:<objectId>"
  reason      TEXT NOT NULL,
  owner       TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  expires_at  TEXT                    -- empty means no expiry
);
CREATE INDEX IF NOT EXISTS idx_exceptions_tenant ON drift_exceptions(tenant_id);

CREATE TABLE IF NOT EXISTS drift_findings (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id   TEXT NOT NULL,
  template_id TEXT NOT NULL,
  class       TEXT NOT NULL,          -- missing | changed | disabled | extra
  severity    TEXT NOT NULL,          -- critical | warning | info
  name        TEXT NOT NULL,
  detail      TEXT NOT NULL DEFAULT '',
  first_seen  TEXT NOT NULL,
  last_seen   TEXT NOT NULL,
  resolved_at TEXT,
  notified_at TEXT,
  UNIQUE(tenant_id, template_id, class)
);
CREATE INDEX IF NOT EXISTS idx_findings_open ON drift_findings(tenant_id, resolved_at);

CREATE TABLE IF NOT EXISTS kv (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`

// Finding is one way a client's tenant departs from the standard.
type Finding struct {
	ID         int64  `json:"id"`
	TenantID   string `json:"tenantId"`
	TemplateID string `json:"templateId"`
	Class      string `json:"class"`
	Severity   string `json:"severity"`
	Name       string `json:"name"`
	Detail     string `json:"detail"`
	FirstSeen  string `json:"firstSeen"`
	LastSeen   string `json:"lastSeen"`
	ResolvedAt string `json:"resolvedAt,omitempty"`
	NotifiedAt string `json:"notifiedAt,omitempty"`

	AckedBy      string `json:"ackedBy,omitempty"`
	AckedAt      string `json:"ackedAt,omitempty"`
	AckNote      string `json:"ackNote,omitempty"`
	SnoozedUntil string `json:"snoozedUntil,omitempty"`
	State        string `json:"state"` // new | acknowledged | snoozed, as of the moment it was read
}

// Exception silences matching drift for one client until it expires.
type Exception struct {
	ID         int64  `json:"id"`
	TenantID   string `json:"tenantId"`
	TemplateID string `json:"templateId"`
	Reason     string `json:"reason"`
	Owner      string `json:"owner"`
	CreatedAt  string `json:"createdAt"`
	ExpiresAt  string `json:"expiresAt,omitempty"`
}

// Active reports whether the exception still applies at t.
func (e Exception) Active(t time.Time) bool {
	if e.ExpiresAt == "" {
		return true
	}
	exp, err := time.Parse(time.RFC3339, e.ExpiresAt)
	if err != nil {
		return true // an unreadable date must not quietly end a silence early or late; keep it and let a person see it
	}
	return t.Before(exp)
}

// ---- per-client values ----

func (s *Store) SetTokens(tenantID string, tokens map[string]string) error {
	b, err := json.Marshal(tokens)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO tenant_tokens (tenant_id, tokens, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(tenant_id) DO UPDATE SET tokens = excluded.tokens, updated_at = excluded.updated_at`,
		tenantID, string(b), now())
	return err
}

// Tokens returns the stored values for a client, or an empty map.
func (s *Store) Tokens(tenantID string) (map[string]string, error) {
	var raw string
	err := s.db.QueryRow(`SELECT tokens FROM tenant_tokens WHERE tenant_id = ?`, tenantID).Scan(&raw)
	if err == sql.ErrNoRows {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ---- exceptions ----

func (s *Store) AddException(e Exception) (int64, error) {
	if e.CreatedAt == "" {
		e.CreatedAt = now()
	}
	res, err := s.db.Exec(`INSERT INTO drift_exceptions (tenant_id, template_id, reason, owner, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`, e.TenantID, e.TemplateID, e.Reason, e.Owner, e.CreatedAt, nullIfEmpty(e.ExpiresAt))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) DeleteException(id int64) error {
	_, err := s.db.Exec(`DELETE FROM drift_exceptions WHERE id = ?`, id)
	return err
}

func (s *Store) Exceptions(tenantID string) ([]Exception, error) {
	rows, err := s.db.Query(`SELECT id, tenant_id, template_id, reason, owner, created_at, COALESCE(expires_at,'')
		FROM drift_exceptions WHERE tenant_id = ? ORDER BY created_at`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Exception{}
	for rows.Next() {
		var e Exception
		if err := rows.Scan(&e.ID, &e.TenantID, &e.TemplateID, &e.Reason, &e.Owner, &e.CreatedAt, &e.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---- findings ----

// FindingChange says what ApplyFindings did, so the caller can decide who to tell.
type FindingChange struct {
	Opened   []Finding // new, or came back after being resolved
	Resolved []Finding // were open, are no longer seen
}

// ApplyFindings brings the stored findings for one client in line with what the
// latest check saw: new ones are opened, still-present ones are refreshed, and
// open ones that were not seen are resolved. A finding that was resolved and
// reappears is opened again as new, so the person is told again.
//
// keep, when set, names open findings that must not be resolved because this
// check could not look at them (the application lacked permission for that kind).
// Not looking is not the same as fixed.
func (s *Store) ApplyFindings(tenantID string, seen []Finding, keep func(Finding) bool, at time.Time) (*FindingChange, error) {
	ts := at.UTC().Format(time.RFC3339)
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	change := &FindingChange{}
	seenKey := map[string]bool{}
	for _, f := range seen {
		f.TenantID = tenantID
		seenKey[f.TemplateID+"|"+f.Class] = true
		var id int64
		var resolved sql.NullString
		err := tx.QueryRow(`SELECT id, resolved_at FROM drift_findings WHERE tenant_id = ? AND template_id = ? AND class = ?`,
			tenantID, f.TemplateID, f.Class).Scan(&id, &resolved)
		switch {
		case err == sql.ErrNoRows:
			res, err := tx.Exec(`INSERT INTO drift_findings (tenant_id, template_id, class, severity, name, detail, first_seen, last_seen)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, tenantID, f.TemplateID, f.Class, f.Severity, f.Name, f.Detail, ts, ts)
			if err != nil {
				return nil, err
			}
			f.ID, _ = res.LastInsertId()
			f.FirstSeen, f.LastSeen = ts, ts
			change.Opened = append(change.Opened, f)
		case err != nil:
			return nil, err
		case resolved.Valid:
			if _, err := tx.Exec(`UPDATE drift_findings SET severity = ?, name = ?, detail = ?, first_seen = ?, last_seen = ?,
				resolved_at = NULL, notified_at = NULL,
				ack_by = NULL, ack_at = NULL, ack_note = NULL, snoozed_until = NULL WHERE id = ?`, f.Severity, f.Name, f.Detail, ts, ts, id); err != nil {
				return nil, err
			}
			f.ID, f.FirstSeen, f.LastSeen = id, ts, ts
			change.Opened = append(change.Opened, f)
		default:
			if _, err := tx.Exec(`UPDATE drift_findings SET severity = ?, name = ?, detail = ?, last_seen = ? WHERE id = ?`,
				f.Severity, f.Name, f.Detail, ts, id); err != nil {
				return nil, err
			}
		}
	}

	rows, err := tx.Query(`SELECT id, template_id, class, severity, name, detail, first_seen, last_seen
		FROM drift_findings WHERE tenant_id = ? AND resolved_at IS NULL`, tenantID)
	if err != nil {
		return nil, err
	}
	var gone []Finding
	for rows.Next() {
		var f Finding
		f.TenantID = tenantID
		if err := rows.Scan(&f.ID, &f.TemplateID, &f.Class, &f.Severity, &f.Name, &f.Detail, &f.FirstSeen, &f.LastSeen); err != nil {
			rows.Close()
			return nil, err
		}
		if !seenKey[f.TemplateID+"|"+f.Class] && (keep == nil || !keep(f)) {
			gone = append(gone, f)
		}
	}
	rows.Close()
	for _, f := range gone {
		if _, err := tx.Exec(`UPDATE drift_findings SET resolved_at = ? WHERE id = ?`, ts, f.ID); err != nil {
			return nil, err
		}
		f.ResolvedAt = ts
		change.Resolved = append(change.Resolved, f)
	}
	return change, tx.Commit()
}

// OpenFindings lists unresolved findings for one client, worst first.
func (s *Store) OpenFindings(tenantID string) ([]Finding, error) {
	return s.findings(`WHERE tenant_id = ? AND resolved_at IS NULL`, tenantID)
}

// AllOpenFindings lists unresolved findings across every client.
func (s *Store) AllOpenFindings() ([]Finding, error) {
	return s.findings(`WHERE resolved_at IS NULL`)
}

func (s *Store) findings(where string, args ...any) ([]Finding, error) {
	rows, err := s.db.Query(`SELECT id, tenant_id, template_id, class, severity, name, detail, first_seen, last_seen,
		COALESCE(resolved_at,''), COALESCE(notified_at,''), COALESCE(ack_by,''), COALESCE(ack_at,''), COALESCE(ack_note,''), COALESCE(snoozed_until,'')
		FROM drift_findings `+where+`
		ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, tenant_id, name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Finding{}
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.TenantID, &f.TemplateID, &f.Class, &f.Severity, &f.Name, &f.Detail,
			&f.FirstSeen, &f.LastSeen, &f.ResolvedAt, &f.NotifiedAt, &f.AckedBy, &f.AckedAt, &f.AckNote, &f.SnoozedUntil); err != nil {
			return nil, err
		}
		f.State = f.StateAt(time.Now())
		out = append(out, f)
	}
	return out, rows.Err()
}

// MarkNotified records that these findings have been told to a person, so a
// finding is announced once, not on every check.
func (s *Store) MarkNotified(ids []int64, at time.Time) error {
	ts := at.UTC().Format(time.RFC3339)
	for _, id := range ids {
		if _, err := s.db.Exec(`UPDATE drift_findings SET notified_at = ? WHERE id = ?`, ts, id); err != nil {
			return err
		}
	}
	return nil
}

// ---- small key/value (last digest time) ----

func (s *Store) KV(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM kv WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func (s *Store) SetKV(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}
