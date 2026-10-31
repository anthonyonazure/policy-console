package store

import (
	"errors"
	"time"
)

// MinRetentionDays is the shortest history the console will ever keep. A setting
// of 0 days must never mean "everything", so anything below this is refused.
const MinRetentionDays = 30

// PruneVersions deletes captured versions older than the cutoff, with three
// protections that no setting can switch off:
//
//   - the newest version of every object is always kept, so history never loses
//     the current state of anything;
//   - any version a run points at (as its before or after) is kept, so a revert
//     link in the run log keeps working;
//   - nothing newer than MinRetentionDays is ever deleted.
//
// It returns how many versions were removed.
func (s *Store) PruneVersions(olderThanDays int, now time.Time) (int64, error) {
	if olderThanDays < MinRetentionDays {
		return 0, errors.New("retention below 30 days is refused: a mistyped setting must not delete history")
	}
	cutoff := now.UTC().AddDate(0, 0, -olderThanDays).Format(time.RFC3339)
	res, err := s.db.Exec(`
		DELETE FROM object_versions
		WHERE captured_at < ?
		  AND version < (SELECT MAX(v2.version) FROM object_versions v2
		                 WHERE v2.tenant_id = object_versions.tenant_id AND v2.kind = object_versions.kind AND v2.object_id = object_versions.object_id)
		  AND NOT EXISTS (SELECT 1 FROM run_items ri
		                  JOIN runs r ON r.id = ri.run_id
		                  WHERE r.tenant_id = object_versions.tenant_id AND ri.kind = object_versions.kind AND ri.object_id = object_versions.object_id
		                    AND (ri.before_ver = object_versions.version OR ri.after_ver = object_versions.version))`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
