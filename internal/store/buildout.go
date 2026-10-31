package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

const buildoutSchema = `
CREATE TABLE IF NOT EXISTS buildouts (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id  TEXT NOT NULL,
  answers    TEXT NOT NULL,
  plan       TEXT NOT NULL,
  steps      TEXT NOT NULL,            -- step id -> state, as JSON
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_buildouts_tenant ON buildouts(tenant_id);
`

// StepState is where one step of a build out stands.
type StepState struct {
	State  string `json:"state"` // pending | done | skipped | failed
	By     string `json:"by,omitempty"`
	At     string `json:"at,omitempty"`
	Note   string `json:"note,omitempty"`
	RunID  int64  `json:"runId,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Buildout is one client's build plan and how far it has got.
type Buildout struct {
	ID        int64                `json:"id"`
	TenantID  string               `json:"tenantId"`
	Answers   json.RawMessage      `json:"answers"`
	Plan      json.RawMessage      `json:"plan"`
	Steps     map[string]StepState `json:"steps"`
	CreatedBy string               `json:"createdBy"`
	CreatedAt string               `json:"createdAt"`
}

func (s *Store) CreateBuildout(tenantID string, answers, plan []byte, stepIDs []string, by string) (int64, error) {
	steps := map[string]StepState{}
	for _, id := range stepIDs {
		steps[id] = StepState{State: "pending"}
	}
	sj, _ := json.Marshal(steps)
	res, err := s.db.Exec(`INSERT INTO buildouts (tenant_id, answers, plan, steps, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		tenantID, string(answers), string(plan), string(sj), by, now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) scanBuildout(row rowScanner) (*Buildout, error) {
	var b Buildout
	var a, p, st string
	if err := row.Scan(&b.ID, &b.TenantID, &a, &p, &st, &b.CreatedBy, &b.CreatedAt); err != nil {
		return nil, err
	}
	b.Answers, b.Plan = json.RawMessage(a), json.RawMessage(p)
	if err := json.Unmarshal([]byte(st), &b.Steps); err != nil {
		return nil, err
	}
	return &b, nil
}

const buildoutCols = `SELECT id, tenant_id, answers, plan, steps, created_by, created_at FROM buildouts`

func (s *Store) Buildout(id int64) (*Buildout, error) {
	b, err := s.scanBuildout(s.db.QueryRow(buildoutCols+` WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return b, err
}

func (s *Store) Buildouts(tenantID string) ([]Buildout, error) {
	rows, err := s.db.Query(buildoutCols+` WHERE tenant_id = ? ORDER BY id DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Buildout{}
	for rows.Next() {
		b, err := s.scanBuildout(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *b)
	}
	return out, rows.Err()
}

// SetStep records the outcome of one step. Steps are updated one at a time, in a
// transaction, so two people finishing different steps never overwrite each other.
func (s *Store) SetStep(buildoutID int64, stepID string, st StepState) error {
	if st.At == "" {
		st.At = time.Now().UTC().Format(time.RFC3339)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw string
	if err := tx.QueryRow(`SELECT steps FROM buildouts WHERE id = ?`, buildoutID).Scan(&raw); err != nil {
		return errors.New("no such build out")
	}
	steps := map[string]StepState{}
	if err := json.Unmarshal([]byte(raw), &steps); err != nil {
		return err
	}
	if _, ok := steps[stepID]; !ok {
		return errors.New("no such step")
	}
	steps[stepID] = st
	b, _ := json.Marshal(steps)
	if _, err := tx.Exec(`UPDATE buildouts SET steps = ? WHERE id = ?`, string(b), buildoutID); err != nil {
		return err
	}
	return tx.Commit()
}
