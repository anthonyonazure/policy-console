package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

const librarySchema = `
CREATE TABLE IF NOT EXISTS library_templates (
  id          TEXT PRIMARY KEY,
  category    TEXT NOT NULL,
  state       TEXT NOT NULL,          -- active | retired
  cloned_from TEXT NOT NULL DEFAULT '',
  created_by  TEXT NOT NULL,
  created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS library_versions (
  template_id TEXT NOT NULL,
  version     INTEGER NOT NULL,
  state       TEXT NOT NULL,          -- draft | published
  body        TEXT NOT NULL,
  hash        TEXT NOT NULL,
  parent_hash TEXT NOT NULL DEFAULT '',
  author      TEXT NOT NULL,
  reason      TEXT NOT NULL DEFAULT '',
  approver    TEXT NOT NULL DEFAULT '',
  created_at  TEXT NOT NULL,
  PRIMARY KEY (template_id, version)
);
`

// LibraryTemplate is a template the operator owns and can edit.
type LibraryTemplate struct {
	ID         string `json:"id"`
	Category   string `json:"category"`
	State      string `json:"state"`
	ClonedFrom string `json:"clonedFrom,omitempty"`
	CreatedBy  string `json:"createdBy"`
	CreatedAt  string `json:"createdAt"`
	Published  int    `json:"publishedVersion"` // 0 when only a draft exists
	HasDraft   bool   `json:"hasDraft"`
}

// LibraryVersion is one saved state of a template.
type LibraryVersion struct {
	TemplateID string `json:"templateId"`
	Version    int    `json:"version"`
	State      string `json:"state"`
	Body       string `json:"body,omitempty"`
	Hash       string `json:"hash"`
	ParentHash string `json:"parentHash,omitempty"`
	Author     string `json:"author"`
	Reason     string `json:"reason,omitempty"`
	Approver   string `json:"approver,omitempty"`
	CreatedAt  string `json:"createdAt"`
}

var (
	ErrTemplateExists = errors.New("a template with that id already exists")
	ErrNoTemplate     = errors.New("no such template")
)

// CreateLibraryTemplate adds a template with a first draft.
func (s *Store) CreateLibraryTemplate(id, category, clonedFrom, author string, body []byte) error {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(category) == "" {
		return errors.New("a template needs an id and a category")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	_ = tx.QueryRow(`SELECT COUNT(*) FROM library_templates WHERE id = ?`, id).Scan(&n)
	if n > 0 {
		return ErrTemplateExists
	}
	ts := now()
	if _, err := tx.Exec(`INSERT INTO library_templates (id, category, state, cloned_from, created_by, created_at) VALUES (?, ?, 'active', ?, ?, ?)`,
		id, category, clonedFrom, author, ts); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO library_versions (template_id, version, state, body, hash, author, created_at) VALUES (?, 1, 'draft', ?, ?, ?, ?)`,
		id, string(body), Hash(body), author, ts); err != nil {
		return err
	}
	return tx.Commit()
}

// SaveDraft replaces the working draft. Only one draft exists per template and it
// always has the highest version number.
func (s *Store) SaveDraft(id, author string, body []byte) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var maxV int
	var state string
	err = tx.QueryRow(`SELECT version, state FROM library_versions WHERE template_id = ? ORDER BY version DESC LIMIT 1`, id).Scan(&maxV, &state)
	if err == sql.ErrNoRows {
		return ErrNoTemplate
	}
	if err != nil {
		return err
	}
	if state == "draft" {
		_, err = tx.Exec(`UPDATE library_versions SET body = ?, hash = ?, author = ?, created_at = ? WHERE template_id = ? AND version = ?`,
			string(body), Hash(body), author, now(), id, maxV)
	} else {
		var parent string
		_ = tx.QueryRow(`SELECT hash FROM library_versions WHERE template_id = ? AND version = ?`, id, maxV).Scan(&parent)
		_, err = tx.Exec(`INSERT INTO library_versions (template_id, version, state, body, hash, parent_hash, author, created_at) VALUES (?, ?, 'draft', ?, ?, ?, ?, ?)`,
			id, maxV+1, string(body), Hash(body), parent, author, now())
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

// PublishDraft makes the draft the current version. The approver is recorded, and
// a reason is required so every published change can be explained later.
func (s *Store) PublishDraft(id, approver, reason string) (int, error) {
	if strings.TrimSpace(reason) == "" || strings.TrimSpace(approver) == "" {
		return 0, errors.New("publishing needs an approver and a reason")
	}
	res, err := s.db.Exec(`UPDATE library_versions SET state = 'published', approver = ?, reason = ?, created_at = ?
		WHERE template_id = ? AND state = 'draft'`, approver, reason, now(), id)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, errors.New("there is no draft to publish")
	}
	var v int
	err = s.db.QueryRow(`SELECT MAX(version) FROM library_versions WHERE template_id = ?`, id).Scan(&v)
	return v, err
}

// DiscardDraft throws the working draft away, leaving the published version.
func (s *Store) DiscardDraft(id string) error {
	_, err := s.db.Exec(`DELETE FROM library_versions WHERE template_id = ? AND state = 'draft' AND version > 1`, id)
	return err
}

// SetLibraryState retires or restores a template. A retired template is no longer
// loaded, but its history stays.
func (s *Store) SetLibraryState(id, state string) error {
	res, err := s.db.Exec(`UPDATE library_templates SET state = ? WHERE id = ?`, state, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoTemplate
	}
	return nil
}

func (s *Store) LibraryTemplates() ([]LibraryTemplate, error) {
	rows, err := s.db.Query(`SELECT t.id, t.category, t.state, t.cloned_from, t.created_by, t.created_at,
		COALESCE((SELECT MAX(version) FROM library_versions v WHERE v.template_id = t.id AND v.state = 'published'), 0),
		EXISTS (SELECT 1 FROM library_versions v WHERE v.template_id = t.id AND v.state = 'draft')
		FROM library_templates t ORDER BY t.category, t.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LibraryTemplate{}
	for rows.Next() {
		var t LibraryTemplate
		if err := rows.Scan(&t.ID, &t.Category, &t.State, &t.ClonedFrom, &t.CreatedBy, &t.CreatedAt, &t.Published, &t.HasDraft); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// LibraryVersions lists a template's versions, newest first. Bodies are included
// only when withBody is true.
func (s *Store) LibraryVersions(id string, withBody bool) ([]LibraryVersion, error) {
	rows, err := s.db.Query(`SELECT template_id, version, state, body, hash, parent_hash, author, reason, approver, created_at
		FROM library_versions WHERE template_id = ? ORDER BY version DESC`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LibraryVersion{}
	for rows.Next() {
		var v LibraryVersion
		if err := rows.Scan(&v.TemplateID, &v.Version, &v.State, &v.Body, &v.Hash, &v.ParentHash, &v.Author, &v.Reason, &v.Approver, &v.CreatedAt); err != nil {
			return nil, err
		}
		if !withBody {
			v.Body = ""
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// PublishedLibrary returns every active template's current published body, for
// loading into the catalog.
func (s *Store) PublishedLibrary() (map[string]struct {
	Category string
	Body     []byte
}, error) {
	rows, err := s.db.Query(`SELECT t.id, t.category, v.body FROM library_templates t
		JOIN library_versions v ON v.template_id = t.id AND v.state = 'published'
		WHERE t.state = 'active'
		  AND v.version = (SELECT MAX(version) FROM library_versions w WHERE w.template_id = t.id AND w.state = 'published')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]struct {
		Category string
		Body     []byte
	}{}
	for rows.Next() {
		var id, cat, body string
		if err := rows.Scan(&id, &cat, &body); err != nil {
			return nil, err
		}
		out[id] = struct {
			Category string
			Body     []byte
		}{cat, []byte(body)}
	}
	return out, rows.Err()
}

var _ = time.Now
