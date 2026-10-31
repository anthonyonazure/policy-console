package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const tailorSchema = `
CREATE TABLE IF NOT EXISTS client_profiles (
  tenant_id   TEXT PRIMARY KEY,
  profile     TEXT NOT NULL,           -- flags and name prefix as JSON
  updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS overlays (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id   TEXT NOT NULL,
  template_id TEXT NOT NULL,
  op          TEXT NOT NULL,           -- exclude | modify
  patch       TEXT NOT NULL DEFAULT '',-- JSON merge patch, for modify
  reason      TEXT NOT NULL,
  owner       TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  expires_at  TEXT,
  UNIQUE(tenant_id, template_id)
);
`

// Profile is what is true of one client that changes what they should get.
type Profile struct {
	NamePrefix    string   `json:"namePrefix"`    // put in front of every policy name deployed to this client
	ThirdPartyEDR bool     `json:"thirdPartyEDR"` // another product does endpoint protection, so Defender policies are not expected
	RMMPatching   bool     `json:"rmmPatching"`   // a management tool patches devices
	Regulated     bool     `json:"regulated"`     // HIPAA, CMMC or similar applies
	BYOD          bool     `json:"byod"`          // staff use their own phones
	Platforms     []string `json:"platforms"`     // Windows, macOS, iOS, Android
	Notes         string   `json:"notes"`
}

func (s *Store) SetProfile(tenantID string, p Profile) error {
	// The space after a separator is part of the prefix ("ACME | "), so only leading
	// space is removed, and a prefix of nothing but spaces means no prefix.
	if strings.TrimSpace(p.NamePrefix) == "" {
		p.NamePrefix = ""
	}
	p.NamePrefix = strings.TrimLeft(p.NamePrefix, " ")
	if len(p.NamePrefix) > 40 {
		return errors.New("the name prefix is too long (40 characters at most)")
	}
	b, _ := json.Marshal(p)
	_, err := s.db.Exec(`INSERT INTO client_profiles (tenant_id, profile, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(tenant_id) DO UPDATE SET profile = excluded.profile, updated_at = excluded.updated_at`, tenantID, string(b), now())
	return err
}

// GetProfile returns the client's profile, or an empty one.
func (s *Store) GetProfile(tenantID string) (Profile, error) {
	var raw string
	err := s.db.QueryRow(`SELECT profile FROM client_profiles WHERE tenant_id = ?`, tenantID).Scan(&raw)
	if err == sql.ErrNoRows {
		return Profile{}, nil
	}
	if err != nil {
		return Profile{}, err
	}
	var p Profile
	return p, json.Unmarshal([]byte(raw), &p)
}

// Overlay changes one template for one client without copying it.
type Overlay struct {
	ID         int64  `json:"id"`
	TenantID   string `json:"tenantId"`
	TemplateID string `json:"templateId"`
	Op         string `json:"op"` // exclude | modify
	Patch      string `json:"patch,omitempty"`
	Reason     string `json:"reason"`
	Owner      string `json:"owner"`
	CreatedAt  string `json:"createdAt"`
	ExpiresAt  string `json:"expiresAt,omitempty"`
}

// Active reports whether the overlay still applies at t. An expired overlay stops
// applying, so the client goes back to the standard and a person is not left
// carrying an exception nobody remembers.
func (o Overlay) Active(t time.Time) bool {
	if o.ExpiresAt == "" {
		return true
	}
	exp, err := time.Parse(time.RFC3339, o.ExpiresAt)
	return err != nil || t.Before(exp)
}

// SetOverlay adds or replaces the overlay for a template. A reason and an owner
// are required so that every departure from the standard can be explained later.
func (s *Store) SetOverlay(o Overlay) (int64, error) {
	if o.Op != "exclude" && o.Op != "modify" {
		return 0, errors.New(`an overlay is either "exclude" or "modify"`)
	}
	if strings.TrimSpace(o.Reason) == "" || strings.TrimSpace(o.Owner) == "" {
		return 0, errors.New("an overlay needs a reason and an owner")
	}
	if o.Op == "modify" {
		var probe map[string]any
		if err := json.Unmarshal([]byte(o.Patch), &probe); err != nil || len(probe) == 0 {
			return 0, errors.New("a modify overlay needs a JSON patch with at least one setting")
		}
	} else {
		o.Patch = ""
	}
	if o.CreatedAt == "" {
		o.CreatedAt = now()
	}
	_, err := s.db.Exec(`INSERT INTO overlays (tenant_id, template_id, op, patch, reason, owner, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(tenant_id, template_id) DO UPDATE SET op = excluded.op, patch = excluded.patch, reason = excluded.reason,
		  owner = excluded.owner, created_at = excluded.created_at, expires_at = excluded.expires_at`,
		o.TenantID, o.TemplateID, o.Op, o.Patch, o.Reason, o.Owner, o.CreatedAt, nullIfEmpty(o.ExpiresAt))
	if err != nil {
		return 0, err
	}
	var id int64
	err = s.db.QueryRow(`SELECT id FROM overlays WHERE tenant_id = ? AND template_id = ?`, o.TenantID, o.TemplateID).Scan(&id)
	return id, err
}

func (s *Store) DeleteOverlay(id int64) error {
	_, err := s.db.Exec(`DELETE FROM overlays WHERE id = ?`, id)
	return err
}

func (s *Store) Overlays(tenantID string) ([]Overlay, error) {
	rows, err := s.db.Query(`SELECT id, tenant_id, template_id, op, patch, reason, owner, created_at, COALESCE(expires_at,'')
		FROM overlays WHERE tenant_id = ? ORDER BY template_id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Overlay{}
	for rows.Next() {
		var o Overlay
		if err := rows.Scan(&o.ID, &o.TenantID, &o.TemplateID, &o.Op, &o.Patch, &o.Reason, &o.Owner, &o.CreatedAt, &o.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}
