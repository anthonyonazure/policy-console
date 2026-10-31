package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/anthonyonazure/policy-console/internal/consent"
	"github.com/anthonyonazure/policy-console/internal/store"
)

type consentReq struct {
	Profile string `json:"profile"` // read | write
	Hash    string `json:"hash"`    // from the preview being confirmed
	Confirm bool   `json:"confirm"`
}

// appFor is the application id that holds a profile's permissions. The write
// profile is the long standing registration; the read profile is optional and,
// when absent, cannot be consented.
func (s *Server) appFor(profile string) string {
	switch profile {
	case consent.ProfileWrite:
		return s.Cfg.ClientID
	case consent.ProfilePlanner:
		return s.Cfg.PlannerClientID
	case consent.ProfileRead:
		return s.Cfg.ReadClientID
	}
	return ""
}

// consentPlan reads the client and says what a grant would do. It writes nothing
// to the client; it does store what it saw, so the consent view stays current.
func (s *Server) consentPlan(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("id")
	req, err := body[consentReq](r)
	if err != nil {
		fail(w, 400, errors.New(`expected {"profile": "read" or "write"}`))
		return
	}
	api, claims, err := s.consentSession(r, tenantID, req.Profile)
	if err != nil {
		fail(w, statusFor(err), err)
		return
	}
	_ = claims
	plan, err := consent.BuildPlan(r.Context(), api, tenantID, req.Profile, s.appFor(req.Profile))
	if err != nil {
		fail(w, 502, err)
		return
	}
	s.rememberConsent(tenantID, plan)
	writeJSON(w, 200, plan)
}

// consentApply grants the permissions from a previewed plan, then verifies.
func (s *Server) consentApply(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("id")
	req, err := body[consentReq](r)
	if err != nil {
		fail(w, 400, errors.New(`expected {"profile", "hash", "confirm": true}`))
		return
	}
	if s.Cfg.ReadOnly {
		fail(w, 403, errors.New("the console is in read-only mode, so it will not grant anything in a client"))
		return
	}
	if !req.Confirm || req.Hash == "" {
		fail(w, 400, errors.New("preview first, then confirm with the preview's hash: granting permissions is a change to the client's tenant"))
		return
	}
	api, _, err := s.consentSession(r, tenantID, req.Profile)
	if err != nil {
		fail(w, statusFor(err), err)
		return
	}
	confirmed := &consent.Plan{TenantID: tenantID, Profile: req.Profile, AppID: s.appFor(req.Profile), Hash: req.Hash}

	runID, _ := s.Store.StartRun(store.Run{TenantID: tenantID, Action: "consent", Mode: "live", Actor: actor(r)})
	res, err := consent.Apply(r.Context(), api, confirmed, nil)
	if res != nil {
		for _, o := range res.Outcomes {
			_ = s.Store.AddRunItem(store.RunItem{RunID: runID, Kind: "consent:" + req.Profile, Name: o.Permission, Result: o.Result, Detail: o.Detail})
		}
		if res.Verified != nil {
			s.rememberConsent(tenantID, res.Verified)
		}
	}
	summary := "granted and verified"
	if err != nil {
		summary = "failed: " + err.Error()
	}
	_ = s.Store.FinishRun(runID, summary)
	if err != nil {
		code := 502
		if errors.Is(err, consent.ErrPlanChanged) {
			code = 409
		}
		writeJSON(w, code, map[string]any{"error": err.Error(), "result": res})
		return
	}
	writeJSON(w, 200, res)
}

// consentStatus shows the last verified state per kind, for both registrations.
func (s *Server) consentStatus(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("id")
	out := map[string]any{}
	for _, profile := range []string{consent.ProfileRead, consent.ProfileWrite} {
		have, err := s.Store.Consents(tenantID, profile)
		if err != nil {
			fail(w, 500, err)
			return
		}
		granted := map[string]bool{}
		for p := range have {
			granted[p] = true
		}
		out[profile] = map[string]any{"configured": s.appFor(profile) != "", "kinds": consent.KindStates(profile, granted)}
	}
	writeJSON(w, 200, out)
}

// consentSession fetches the operator's delegated token for this client and
// checks it is for the right tenant and a role that can grant. The token lives
// for this request only.
func (s *Server) consentSession(r *http.Request, tenantID, profile string) (consent.API, consent.Claims, error) {
	if profile != consent.ProfileRead && profile != consent.ProfileWrite && profile != consent.ProfilePlanner {
		return nil, consent.Claims{}, badRequest(errors.New(`profile must be "read", "write" or "planner"`))
	}
	if profile == consent.ProfilePlanner && tenantID != s.Cfg.TenantID {
		return nil, consent.Claims{}, badRequest(errors.New("the planner profile applies only to the console's own tenant"))
	}
	if s.appFor(profile) == "" {
		return nil, consent.Claims{}, badRequest(fmt.Errorf("no application is configured for the %s profile (PC_%sCLIENT_ID)", profile, map[string]string{"read": "READ_", "write": ""}[profile]))
	}
	if t, err := s.Store.Tenant(tenantID); err != nil || t == nil {
		return nil, consent.Claims{}, notFound(errors.New("unknown tenant"))
	}
	if s.ConsentTokens == nil || s.ConsentAPI == nil {
		return nil, consent.Claims{}, errors.New("consent is not configured")
	}
	tok, err := s.ConsentTokens.Token(r.Context(), tenantID)
	if err != nil {
		return nil, consent.Claims{}, failedPrecondition(err)
	}
	claims, err := consent.ReadClaims(tok)
	if err != nil {
		return nil, consent.Claims{}, failedPrecondition(err)
	}
	if err := consent.Preflight(claims, tenantID); err != nil {
		return nil, claims, failedPrecondition(err)
	}
	return s.ConsentAPI(tok), claims, nil
}

func (s *Server) rememberConsent(tenantID string, p *consent.Plan) {
	var all []string
	for _, it := range p.Items {
		if it.RoleID != "" { // only permissions Microsoft actually offers are judged present or absent
			all = append(all, it.Permission)
		}
	}
	_ = s.Store.SaveConsents(tenantID, p.Profile, p.GrantedSet(), all, time.Now())
}

type statusErr struct {
	code int
	err  error
}

func (e statusErr) Error() string { return e.err.Error() }
func (e statusErr) Unwrap() error { return e.err }

func badRequest(err error) error         { return statusErr{400, err} }
func notFound(err error) error           { return statusErr{404, err} }
func failedPrecondition(err error) error { return statusErr{412, err} }

func statusFor(err error) int {
	var se statusErr
	if errors.As(err, &se) {
		return se.code
	}
	if strings.Contains(err.Error(), "not configured") {
		return 503
	}
	return 500
}
