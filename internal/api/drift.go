package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/anthonyonazure/policy-console/internal/store"
)

// driftStatus shows what is open for one client and which exceptions apply.
func (s *Server) driftStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	open, err := s.Store.OpenFindings(id)
	if err != nil {
		fail(w, 500, err)
		return
	}
	ex, err := s.Store.Exceptions(id)
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"open": open, "exceptions": ex})
}

// driftCheck runs the same check the scheduler runs, now. Critical findings not
// yet announced are announced, exactly as they would be overnight.
func (s *Server) driftCheck(w http.ResponseWriter, r *http.Request) {
	if s.Alerts == nil {
		fail(w, 503, fmt.Errorf("drift checking is not configured"))
		return
	}
	t, err := s.Store.Tenant(r.PathValue("id"))
	if err != nil || t == nil {
		fail(w, 404, fmt.Errorf("unknown tenant"))
		return
	}
	res, err := s.Alerts.Check(r.Context(), *t)
	if err != nil {
		fail(w, 502, err)
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) getTokens(w http.ResponseWriter, r *http.Request) {
	tok, err := s.Store.Tokens(r.PathValue("id"))
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"tokens": tok})
}

// putTokens replaces the values that fill this client's template placeholders.
// Scheduled drift checks use them, so the standard is compared as it would be
// deployed rather than with placeholders showing up as differences.
func (s *Server) putTokens(w http.ResponseWriter, r *http.Request) {
	req, err := body[struct {
		Tokens map[string]string `json:"tokens"`
	}](r)
	if err != nil || req.Tokens == nil {
		fail(w, 400, fmt.Errorf("expected {\"tokens\": {...}}"))
		return
	}
	if t, err := s.Store.Tenant(r.PathValue("id")); err != nil || t == nil {
		fail(w, 404, fmt.Errorf("unknown tenant"))
		return
	}
	if err := s.Store.SetTokens(r.PathValue("id"), req.Tokens); err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"tokens": req.Tokens})
}

type exceptionReq struct {
	TemplateID string `json:"templateId"`
	Reason     string `json:"reason"`
	Owner      string `json:"owner"`
	ExpiresAt  string `json:"expiresAt"` // RFC 3339 or YYYY-MM-DD; empty for none
}

func (s *Server) addException(w http.ResponseWriter, r *http.Request) {
	req, err := body[exceptionReq](r)
	if err != nil {
		fail(w, 400, err)
		return
	}
	req.TemplateID, req.Reason = strings.TrimSpace(req.TemplateID), strings.TrimSpace(req.Reason)
	if req.TemplateID == "" || req.Reason == "" {
		fail(w, 400, fmt.Errorf("templateId and reason are required: an exception without a reason cannot be reviewed later"))
		return
	}
	if req.Owner = strings.TrimSpace(req.Owner); req.Owner == "" {
		req.Owner = actor(r)
	}
	exp, err := parseExpiry(req.ExpiresAt, time.Now())
	if err != nil {
		fail(w, 400, err)
		return
	}
	id := r.PathValue("id")
	if t, err := s.Store.Tenant(id); err != nil || t == nil {
		fail(w, 404, fmt.Errorf("unknown tenant"))
		return
	}
	exID, err := s.Store.AddException(store.Exception{TenantID: id, TemplateID: req.TemplateID, Reason: req.Reason, Owner: req.Owner, ExpiresAt: exp})
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 201, map[string]any{"id": exID})
}

func (s *Server) deleteException(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, 400, fmt.Errorf("bad id"))
		return
	}
	if err := s.Store.DeleteException(id); err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}

// parseExpiry accepts a date or a timestamp and refuses one already past, since
// an exception that is born expired would silently do nothing.
func parseExpiry(v string, now time.Time) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		d, derr := time.Parse("2006-01-02", v)
		if derr != nil {
			return "", fmt.Errorf("expiresAt must be a date like 2026-12-31 or an RFC 3339 timestamp")
		}
		t = d.Add(24*time.Hour - time.Second) // a date means the whole day
	}
	if !t.After(now) {
		return "", fmt.Errorf("expiresAt is in the past")
	}
	return t.UTC().Format(time.RFC3339), nil
}

type findingReq struct {
	Note  string `json:"note"`
	Until string `json:"until"` // snooze only: a date or RFC 3339 timestamp
}

func findingID(r *http.Request) (int64, error) {
	return strconv.ParseInt(r.PathValue("id"), 10, 64)
}

func findingFail(w http.ResponseWriter, err error) {
	code := 400
	if errors.Is(err, store.ErrNoSuchFinding) {
		code = 404
	}
	fail(w, code, err)
}

// acknowledgeFinding records that the signed in person has seen a finding.
func (s *Server) acknowledgeFinding(w http.ResponseWriter, r *http.Request) {
	id, err := findingID(r)
	if err != nil {
		fail(w, 400, fmt.Errorf("bad id"))
		return
	}
	req, _ := body[findingReq](r)
	if err := s.Store.Acknowledge(id, actor(r), req.Note, time.Now()); err != nil {
		findingFail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"acknowledged": id})
}

func (s *Server) snoozeFinding(w http.ResponseWriter, r *http.Request) {
	id, err := findingID(r)
	if err != nil {
		fail(w, 400, fmt.Errorf("bad id"))
		return
	}
	req, _ := body[findingReq](r)
	until, err := parseExpiry(req.Until, time.Now())
	if err != nil || until == "" {
		fail(w, 400, fmt.Errorf("snooze needs a future date in until"))
		return
	}
	t, _ := time.Parse(time.RFC3339, until)
	if err := s.Store.Snooze(id, actor(r), req.Note, t, time.Now()); err != nil {
		findingFail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"snoozedUntil": until})
}

func (s *Server) reopenFinding(w http.ResponseWriter, r *http.Request) {
	id, err := findingID(r)
	if err != nil {
		fail(w, 400, fmt.Errorf("bad id"))
		return
	}
	if err := s.Store.Reopen(id); err != nil {
		findingFail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"reopened": id})
}
