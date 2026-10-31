package store

import (
	"errors"
	"strings"
	"time"
)

// Finding states a person sees. A finding is "new" until someone takes it,
// "acknowledged" when a named person has seen it, and "snoozed" until a date.
// It becomes resolved on its own when the drift clears (see ApplyFindings).
const (
	StateNew          = "new"
	StateAcknowledged = "acknowledged"
	StateSnoozed      = "snoozed"
)

// lifecycleColumns are added to drift_findings. They are applied as separate
// statements so a database created before this existed is upgraded in place.
var lifecycleColumns = []string{
	`ALTER TABLE drift_findings ADD COLUMN ack_by TEXT`,
	`ALTER TABLE drift_findings ADD COLUMN ack_at TEXT`,
	`ALTER TABLE drift_findings ADD COLUMN ack_note TEXT`,
	`ALTER TABLE drift_findings ADD COLUMN snoozed_until TEXT`,
	`ALTER TABLE rollouts ADD COLUMN template_id TEXT NOT NULL DEFAULT ''`,
}

func (s *Store) migrateLifecycle() error {
	for _, q := range lifecycleColumns {
		if _, err := s.db.Exec(q); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return err
		}
	}
	return nil
}

// StateAt reports a finding's state at time t. A snooze that has run out is "new" again.
func (f Finding) StateAt(t time.Time) string {
	if f.SnoozedUntil != "" {
		if until, err := time.Parse(time.RFC3339, f.SnoozedUntil); err == nil && t.Before(until) {
			return StateSnoozed
		}
		return StateNew
	}
	if f.AckedBy != "" {
		return StateAcknowledged
	}
	return StateNew
}

var ErrNoSuchFinding = errors.New("no open finding with that id")

// Acknowledge records that a named person has seen the finding. It stops the
// finding appearing in the daily digest but keeps it on the fleet board.
func (s *Store) Acknowledge(id int64, by, note string, at time.Time) error {
	if strings.TrimSpace(by) == "" {
		return errors.New("an acknowledgement needs the name of the person")
	}
	return s.touchFinding(`UPDATE drift_findings SET ack_by = ?, ack_at = ?, ack_note = ?, snoozed_until = NULL
		WHERE id = ? AND resolved_at IS NULL`, by, at.UTC().Format(time.RFC3339), note, id)
}

// Snooze hides the finding from the digest until a date, after which it is new again.
func (s *Store) Snooze(id int64, by, note string, until, at time.Time) error {
	if strings.TrimSpace(by) == "" {
		return errors.New("a snooze needs the name of the person")
	}
	if !until.After(at) {
		return errors.New("the snooze must end in the future")
	}
	return s.touchFinding(`UPDATE drift_findings SET ack_by = ?, ack_at = ?, ack_note = ?, snoozed_until = ?
		WHERE id = ? AND resolved_at IS NULL`, by, at.UTC().Format(time.RFC3339), note, until.UTC().Format(time.RFC3339), id)
}

// Reopen clears an acknowledgement or snooze.
func (s *Store) Reopen(id int64) error {
	return s.touchFinding(`UPDATE drift_findings SET ack_by = NULL, ack_at = NULL, ack_note = NULL, snoozed_until = NULL
		WHERE id = ? AND resolved_at IS NULL`, id)
}

func (s *Store) touchFinding(q string, args ...any) error {
	res, err := s.db.Exec(q, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoSuchFinding
	}
	return nil
}
