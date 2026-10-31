package store

import "time"

const consentSchema = `
CREATE TABLE IF NOT EXISTS tenant_consents (
  tenant_id    TEXT NOT NULL,
  registration TEXT NOT NULL,          -- read | write
  permission   TEXT NOT NULL,
  granted_at   TEXT NOT NULL,
  verified_at  TEXT NOT NULL,
  PRIMARY KEY (tenant_id, registration, permission)
);
`

// SaveConsents records what a read-back of the client showed. A permission that
// is present is stamped verified now (and keeps its first granted time); one that
// is absent is removed, so this table only ever says what was last seen to be true.
func (s *Store) SaveConsents(tenantID, registration string, granted map[string]bool, all []string, at time.Time) error {
	ts := at.UTC().Format(time.RFC3339)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, perm := range all {
		if granted[perm] {
			if _, err := tx.Exec(`INSERT INTO tenant_consents (tenant_id, registration, permission, granted_at, verified_at)
				VALUES (?, ?, ?, ?, ?)
				ON CONFLICT(tenant_id, registration, permission) DO UPDATE SET verified_at = excluded.verified_at`,
				tenantID, registration, perm, ts, ts); err != nil {
				return err
			}
		} else if _, err := tx.Exec(`DELETE FROM tenant_consents WHERE tenant_id = ? AND registration = ? AND permission = ?`,
			tenantID, registration, perm); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Consents returns the last verified permissions for one registration.
func (s *Store) Consents(tenantID, registration string) (map[string]string, error) {
	rows, err := s.db.Query(`SELECT permission, verified_at FROM tenant_consents WHERE tenant_id = ? AND registration = ?`, tenantID, registration)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var p, v string
		if err := rows.Scan(&p, &v); err != nil {
			return nil, err
		}
		out[p] = v
	}
	return out, rows.Err()
}
