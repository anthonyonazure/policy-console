package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

const rolloutSchema = `
CREATE TABLE IF NOT EXISTS rollouts (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id   TEXT NOT NULL,
  plan_name   TEXT NOT NULL,
  plan        TEXT NOT NULL,           -- the plan as it was when the rollout was created
  kind        TEXT NOT NULL,
  object_id   TEXT NOT NULL,
  object_name TEXT NOT NULL,
  template_id TEXT NOT NULL DEFAULT '',
  initial     TEXT NOT NULL,           -- what was assigned before the rollout touched it
  state       TEXT NOT NULL,           -- scheduled | running | paused | completed | canceled | error
  created_by  TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL,
  note        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_rollouts_tenant ON rollouts(tenant_id, state);

CREATE TABLE IF NOT EXISTS rollout_rings (
  rollout_id   INTEGER NOT NULL,
  idx          INTEGER NOT NULL,
  name         TEXT NOT NULL,
  spec         TEXT NOT NULL,          -- groups, virtual group, wait and gates for this ring
  state        TEXT NOT NULL,          -- pending | waiting | activated | error
  eligible_at  TEXT,
  activated_at TEXT,
  approved_by  TEXT,
  approved_at  TEXT,
  detail       TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (rollout_id, idx)
);
`

// Rollout is one policy being offered to a client in stages.
type Rollout struct {
	ID         int64           `json:"id"`
	TenantID   string          `json:"tenantId"`
	PlanName   string          `json:"planName"`
	Plan       json.RawMessage `json:"plan"`
	Kind       string          `json:"kind"`
	ObjectID   string          `json:"objectId"`
	ObjectName string          `json:"objectName"`
	TemplateID string          `json:"templateId,omitempty"`
	Initial    json.RawMessage `json:"initial"`
	State      string          `json:"state"`
	CreatedBy  string          `json:"createdBy"`
	CreatedAt  string          `json:"createdAt"`
	UpdatedAt  string          `json:"updatedAt"`
	Note       string          `json:"note"`
	Rings      []RolloutRing   `json:"rings,omitempty"`
}

type RolloutRing struct {
	RolloutID   int64           `json:"rolloutId"`
	Index       int             `json:"index"`
	Name        string          `json:"name"`
	Spec        json.RawMessage `json:"spec"`
	State       string          `json:"state"`
	EligibleAt  string          `json:"eligibleAt,omitempty"`
	ActivatedAt string          `json:"activatedAt,omitempty"`
	ApprovedBy  string          `json:"approvedBy,omitempty"`
	ApprovedAt  string          `json:"approvedAt,omitempty"`
	Detail      string          `json:"detail"`
}

var ErrPayloadBusy = errors.New("this policy is already part of an active rollout")

// CreateRollout stores a rollout and its rings together. A policy can be in only
// one active rollout at a time, because two plans moving the same assignments
// would undo each other.
func (s *Store) CreateRollout(r Rollout, rings []RolloutRing) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var busy int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM rollouts WHERE tenant_id = ? AND kind = ? AND object_id = ?
		AND state IN ('scheduled','running','paused','error')`, r.TenantID, r.Kind, r.ObjectID).Scan(&busy); err != nil {
		return 0, err
	}
	if busy > 0 {
		return 0, ErrPayloadBusy
	}
	ts := now()
	res, err := tx.Exec(`INSERT INTO rollouts (tenant_id, plan_name, plan, kind, object_id, object_name, template_id, initial, state, created_by, created_at, updated_at, note)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, r.TenantID, r.PlanName, string(r.Plan), r.Kind, r.ObjectID, r.ObjectName, r.TemplateID,
		string(r.Initial), r.State, r.CreatedBy, ts, ts, r.Note)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	for _, ring := range rings {
		if _, err := tx.Exec(`INSERT INTO rollout_rings (rollout_id, idx, name, spec, state, eligible_at, detail) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			id, ring.Index, ring.Name, string(ring.Spec), ring.State, nullIfEmpty(ring.EligibleAt), ring.Detail); err != nil {
			return 0, err
		}
	}
	return id, tx.Commit()
}

func (s *Store) Rollout(id int64) (*Rollout, error) {
	r, err := s.scanRollout(s.db.QueryRow(rolloutCols+` WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.Rings, err = s.rings(id)
	return r, err
}

const rolloutCols = `SELECT id, tenant_id, plan_name, plan, kind, object_id, object_name, template_id, initial, state, created_by, created_at, updated_at, note FROM rollouts`

type rowScanner interface{ Scan(...any) error }

func (s *Store) scanRollout(row rowScanner) (*Rollout, error) {
	var r Rollout
	var plan, initial string
	if err := row.Scan(&r.ID, &r.TenantID, &r.PlanName, &plan, &r.Kind, &r.ObjectID, &r.ObjectName, &r.TemplateID, &initial, &r.State, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt, &r.Note); err != nil {
		return nil, err
	}
	r.Plan, r.Initial = json.RawMessage(plan), json.RawMessage(initial)
	return &r, nil
}

func (s *Store) rings(id int64) ([]RolloutRing, error) {
	rows, err := s.db.Query(`SELECT rollout_id, idx, name, spec, state, COALESCE(eligible_at,''), COALESCE(activated_at,''),
		COALESCE(approved_by,''), COALESCE(approved_at,''), detail FROM rollout_rings WHERE rollout_id = ? ORDER BY idx`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RolloutRing
	for rows.Next() {
		var r RolloutRing
		var spec string
		if err := rows.Scan(&r.RolloutID, &r.Index, &r.Name, &spec, &r.State, &r.EligibleAt, &r.ActivatedAt, &r.ApprovedBy, &r.ApprovedAt, &r.Detail); err != nil {
			return nil, err
		}
		r.Spec = json.RawMessage(spec)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Rollouts lists rollouts, newest first. An empty tenant lists every client's.
func (s *Store) Rollouts(tenantID string, activeOnly bool) ([]Rollout, error) {
	q, args := rolloutCols+` WHERE 1=1`, []any{}
	if tenantID != "" {
		q += ` AND tenant_id = ?`
		args = append(args, tenantID)
	}
	if activeOnly {
		q += ` AND state IN ('scheduled','running','paused','error')`
	}
	rows, err := s.db.Query(q+` ORDER BY id DESC`, args...)
	if err != nil {
		return nil, err
	}
	var out []Rollout
	for rows.Next() {
		r, err := s.scanRollout(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, *r)
	}
	rows.Close()
	for i := range out {
		if out[i].Rings, err = s.rings(out[i].ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) SetRolloutState(id int64, state, note string) error {
	_, err := s.db.Exec(`UPDATE rollouts SET state = ?, note = ?, updated_at = ? WHERE id = ?`, state, note, now(), id)
	return err
}

// UpdateRing records what happened to one ring.
func (s *Store) UpdateRing(id int64, idx int, state, eligibleAt, activatedAt, detail string) error {
	_, err := s.db.Exec(`UPDATE rollout_rings SET state = ?, eligible_at = COALESCE(NULLIF(?, ''), eligible_at),
		activated_at = COALESCE(NULLIF(?, ''), activated_at), detail = ? WHERE rollout_id = ? AND idx = ?`,
		state, eligibleAt, activatedAt, detail, id, idx)
	return err
}

// ApproveRing records a named person's approval of a ring.
func (s *Store) ApproveRing(id int64, idx int, by string, at time.Time) error {
	if by == "" {
		return errors.New("an approval needs the name of the person")
	}
	res, err := s.db.Exec(`UPDATE rollout_rings SET approved_by = ?, approved_at = ? WHERE rollout_id = ? AND idx = ?`,
		by, at.UTC().Format(time.RFC3339), id, idx)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("no such ring")
	}
	return nil
}
