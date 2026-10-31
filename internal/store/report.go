package store

import "database/sql"

const reportSchema = `
CREATE TABLE IF NOT EXISTS reports (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id  TEXT NOT NULL,
  baseline   TEXT NOT NULL,
  summary    TEXT NOT NULL,          -- counts as JSON, so the next report can say what moved
  html       TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_tenant ON reports(tenant_id, id DESC);
`

// SavedReport is a dated report kept for a client.
type SavedReport struct {
	ID        int64  `json:"id"`
	TenantID  string `json:"tenantId"`
	Baseline  string `json:"baseline"`
	Summary   string `json:"summary"`
	HTML      string `json:"-"`
	CreatedBy string `json:"createdBy"`
	CreatedAt string `json:"createdAt"`
}

func (s *Store) SaveReport(r SavedReport) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO reports (tenant_id, baseline, summary, html, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		r.TenantID, r.Baseline, r.Summary, r.HTML, r.CreatedBy, now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Reports lists a client's saved reports, newest first.
func (s *Store) Reports(tenantID string) ([]SavedReport, error) {
	rows, err := s.db.Query(`SELECT id, tenant_id, baseline, summary, created_by, created_at FROM reports WHERE tenant_id = ? ORDER BY id DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SavedReport{}
	for rows.Next() {
		var r SavedReport
		if err := rows.Scan(&r.ID, &r.TenantID, &r.Baseline, &r.Summary, &r.CreatedBy, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) Report(id int64) (*SavedReport, error) {
	var r SavedReport
	err := s.db.QueryRow(`SELECT id, tenant_id, baseline, summary, html, created_by, created_at FROM reports WHERE id = ?`, id).
		Scan(&r.ID, &r.TenantID, &r.Baseline, &r.Summary, &r.HTML, &r.CreatedBy, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &r, err
}
