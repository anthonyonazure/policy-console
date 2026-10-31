package store

import (
	"database/sql"

	"github.com/anthonyonazure/policy-console/internal/planner"
)

const plannerSchema = `
CREATE TABLE IF NOT EXISTS planner_plans (
  buildout_id INTEGER PRIMARY KEY,
  plan_id     TEXT NOT NULL,
  created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS planner_tasks (
  buildout_id INTEGER NOT NULL,
  step_id     TEXT NOT NULL,
  task_id     TEXT NOT NULL,
  bucket_id   TEXT NOT NULL,
  hash        TEXT NOT NULL,
  synced_at   TEXT NOT NULL,
  PRIMARY KEY (buildout_id, step_id)
);
`

// PlannerState is what the console has already posted for one build out. It
// satisfies planner.State.
type PlannerState struct {
	s  *Store
	id int64
}

func (s *Store) PlannerState(buildoutID int64) *PlannerState {
	return &PlannerState{s: s, id: buildoutID}
}

func (p *PlannerState) Plan() string {
	var id string
	if err := p.s.db.QueryRow(`SELECT plan_id FROM planner_plans WHERE buildout_id = ?`, p.id).Scan(&id); err != nil && err != sql.ErrNoRows {
		return ""
	}
	return id
}

func (p *PlannerState) SetPlan(planID string) error {
	_, err := p.s.db.Exec(`INSERT OR REPLACE INTO planner_plans (buildout_id, plan_id, created_at) VALUES (?, ?, ?)`, p.id, planID, now())
	return err
}

func (p *PlannerState) Links() map[string]planner.Link {
	out := map[string]planner.Link{}
	rows, err := p.s.db.Query(`SELECT step_id, task_id, bucket_id, hash FROM planner_tasks WHERE buildout_id = ?`, p.id)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var step string
		var l planner.Link
		if rows.Scan(&step, &l.TaskID, &l.BucketID, &l.Hash) == nil {
			out[step] = l
		}
	}
	return out
}

func (p *PlannerState) Save(stepID string, l planner.Link) error {
	_, err := p.s.db.Exec(`INSERT OR REPLACE INTO planner_tasks (buildout_id, step_id, task_id, bucket_id, hash, synced_at) VALUES (?, ?, ?, ?, ?, ?)`,
		p.id, stepID, l.TaskID, l.BucketID, l.Hash, now())
	return err
}
