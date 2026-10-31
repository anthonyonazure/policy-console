// Package api exposes the console over HTTP and serves the browser UI.
package api

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/anthonyonazure/policy-console/internal/alerts"
	"github.com/anthonyonazure/policy-console/internal/auth"
	"github.com/anthonyonazure/policy-console/internal/baseline"
	"github.com/anthonyonazure/policy-console/internal/benchmark"
	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/config"
	"github.com/anthonyonazure/policy-console/internal/consent"
	"github.com/anthonyonazure/policy-console/internal/diff"
	"github.com/anthonyonazure/policy-console/internal/engine"
	"github.com/anthonyonazure/policy-console/internal/equiv"
	"github.com/anthonyonazure/policy-console/internal/impact"
	"github.com/anthonyonazure/policy-console/internal/mstemplates"
	"github.com/anthonyonazure/policy-console/internal/planner"
	"github.com/anthonyonazure/policy-console/internal/praxisprov"
	"github.com/anthonyonazure/policy-console/internal/rollout"
	"github.com/anthonyonazure/policy-console/internal/score"
	"github.com/anthonyonazure/policy-console/internal/store"
)

//go:embed all:web
var webFS embed.FS

type Server struct {
	Cfg    config.Config
	Engine *engine.Engine
	Store  *store.Store
	Cat    *catalog.Catalog
	Auth   *auth.Authenticator
	Alerts *alerts.Service

	// Consent grants the console's permissions inside a client tenant using the
	// operator's own delegated sign-in. Both are set in main; tests replace them.
	builtin map[string]bool // template ids that came with the program

	// Rollouts runs staged rollouts; nil means the feature is off.
	Rollouts *rollout.Runner

	// Impact reads a client's devices for the policy impact preview.
	Impact impact.Source

	// Planner posts build outs to Microsoft Planner; nil means it is not connected.
	// PlannerAsync updates Planner in the background after a step changes (tests
	// leave it off so the update has finished when the request returns).
	Planner      planner.API
	PlannerAsync bool
	plannerMu    sync.Map // build out id -> *sync.Mutex, so two syncs never race and duplicate tasks

	ConsentTokens consent.TokenSource
	ConsentAPI    func(token string) consent.API
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	if s.Auth != nil {
		s.Auth.Routes(mux)
	}

	mux.HandleFunc("GET /api/status", s.status)
	mux.HandleFunc("GET /api/benchmarks", s.benchmarks)
	mux.HandleFunc("POST /api/benchmarks/refresh", s.refreshBenchmarks)
	mux.HandleFunc("POST /api/benchmarks/import-cis", s.importCIS)
	mux.HandleFunc("GET /api/baselines", s.listBaselines)
	mux.HandleFunc("POST /api/baselines/refresh", s.refreshBaselines)
	mux.HandleFunc("GET /api/baselines/templates", s.baselineTemplateAudit)
	mux.HandleFunc("GET /api/templates-overlaps", s.templateOverlaps)
	mux.HandleFunc("GET /api/praxis/provenance", s.praxisProvenance)
	mux.HandleFunc("GET /api/whatif", s.whatIf)
	mux.HandleFunc("POST /api/mstemplates/refresh", s.refreshMSTemplates)
	mux.HandleFunc("GET /api/mstemplates/compare", s.compareMSTemplates)

	mux.HandleFunc("GET /api/templates", s.templates)
	mux.HandleFunc("GET /api/templates/{id}", s.template)

	mux.HandleFunc("GET /api/tenants", s.listTenants)
	mux.HandleFunc("POST /api/tenants", s.addTenant)
	mux.HandleFunc("DELETE /api/tenants/{id}", s.deleteTenant)
	mux.HandleFunc("POST /api/tenants/{id}/probe", s.probeTenant)
	mux.HandleFunc("POST /api/tenants/{id}/snapshot", s.snapshot)
	mux.HandleFunc("POST /api/tenants/{id}/compare", s.compare)
	mux.HandleFunc("POST /api/tenants/{id}/score", s.scoreTenant)
	mux.HandleFunc("POST /api/tenants/{id}/deploy", s.deploy)
	mux.HandleFunc("POST /api/tenants/{id}/revert", s.revert)
	mux.HandleFunc("POST /api/tenants/{id}/modify", s.modify)
	mux.HandleFunc("POST /api/tenants/{id}/enforce", s.enforce)
	mux.HandleFunc("POST /api/tenants/{id}/widen", s.widen)
	mux.HandleFunc("GET /api/tenants/{id}/report-only", s.reportOnly)

	mux.HandleFunc("GET /api/tenants/{id}/objects", s.objects)
	mux.HandleFunc("GET /api/tenants/{id}/history", s.history)
	mux.HandleFunc("GET /api/tenants/{id}/version", s.version)
	mux.HandleFunc("GET /api/tenants/{id}/versiondiff", s.versionDiff)
	mux.HandleFunc("GET /api/tenants/{id}/drift", s.driftStatus)
	mux.HandleFunc("POST /api/tenants/{id}/drift/check", s.driftCheck)
	mux.HandleFunc("GET /api/tenants/{id}/tokens", s.getTokens)
	mux.HandleFunc("PUT /api/tenants/{id}/tokens", s.putTokens)
	mux.HandleFunc("POST /api/tenants/{id}/exceptions", s.addException)
	mux.HandleFunc("DELETE /api/exceptions/{id}", s.deleteException)
	mux.HandleFunc("GET /api/tenants/{id}/consent", s.consentStatus)
	mux.HandleFunc("POST /api/tenants/{id}/consent/plan", s.consentPlan)
	mux.HandleFunc("POST /api/tenants/{id}/consent/apply", s.consentApply)
	mux.HandleFunc("GET /api/assessment/baselines", s.assessmentBaselines)
	mux.HandleFunc("POST /api/tenants/{id}/impact", s.impactPreview)
	mux.HandleFunc("POST /api/findings/{id}/acknowledge", s.acknowledgeFinding)
	mux.HandleFunc("POST /api/findings/{id}/snooze", s.snoozeFinding)
	mux.HandleFunc("POST /api/findings/{id}/reopen", s.reopenFinding)
	mux.HandleFunc("GET /api/tenants/{id}/profile", s.getProfile)
	mux.HandleFunc("PUT /api/tenants/{id}/profile", s.putProfile)
	mux.HandleFunc("GET /api/tenants/{id}/overlays", s.listOverlays)
	mux.HandleFunc("POST /api/tenants/{id}/overlays", s.addOverlay)
	mux.HandleFunc("DELETE /api/overlays/{id}", s.deleteOverlay)
	mux.HandleFunc("GET /api/tenants/{id}/tailoring", s.tailoring)
	mux.HandleFunc("POST /api/buildplan/preview", s.previewBuildplan)
	mux.HandleFunc("POST /api/tenants/{id}/buildouts", s.createBuildout)
	mux.HandleFunc("GET /api/tenants/{id}/buildouts", s.listBuildouts)
	mux.HandleFunc("GET /api/buildouts/{id}", s.getBuildout)
	mux.HandleFunc("POST /api/buildouts/{id}/steps/{step}/preview", s.stepPreview)
	mux.HandleFunc("POST /api/buildouts/{id}/steps/{step}/run", s.stepRun)
	mux.HandleFunc("POST /api/buildouts/{id}/steps/{step}/complete", s.stepComplete)
	mux.HandleFunc("POST /api/buildouts/{id}/steps/{step}/skip", s.stepSkip)
	mux.HandleFunc("GET /api/fleet", s.fleetBoard)
	mux.HandleFunc("POST /api/fleet/apply/preview", s.fleetPreview)
	mux.HandleFunc("POST /api/fleet/apply", s.fleetApply)
	mux.HandleFunc("POST /api/tenants/{id}/reports", s.createReport)
	mux.HandleFunc("GET /api/tenants/{id}/reports", s.listReports)
	mux.HandleFunc("GET /api/reports/{id}", s.viewReport)
	mux.HandleFunc("GET /api/buildouts/{id}/planner", s.plannerExport)
	mux.HandleFunc("GET /api/planner/status", s.plannerStatus)
	mux.HandleFunc("POST /api/buildouts/{id}/planner/preview", s.plannerPreview)
	mux.HandleFunc("POST /api/buildouts/{id}/planner/sync", s.plannerSync)
	mux.HandleFunc("POST /api/tenants/{id}/impact/observed", s.impactObserved)
	mux.HandleFunc("GET /api/tenants/{id}/discovery", s.discovery)
	mux.HandleFunc("GET /api/library", s.libraryList)
	mux.HandleFunc("POST /api/library/templates", s.libraryCreate)
	mux.HandleFunc("PUT /api/library/templates/{id}/draft", s.libraryDraft)
	mux.HandleFunc("POST /api/library/templates/{id}/publish", s.libraryPublish)
	mux.HandleFunc("POST /api/library/templates/{id}/revert", s.libraryRevert)
	mux.HandleFunc("GET /api/library/templates/{id}/versions", s.libraryVersions)
	mux.HandleFunc("GET /api/library/templates/{id}/diff", s.libraryDiff)
	mux.HandleFunc("POST /api/tenants/{id}/impact/access", s.impactAccess)
	mux.HandleFunc("GET /api/rollout-plans", s.rolloutPlans)
	mux.HandleFunc("POST /api/tenants/{id}/rollouts/preview", s.rolloutPreview)
	mux.HandleFunc("POST /api/tenants/{id}/rollouts", s.rolloutCreate)
	mux.HandleFunc("GET /api/tenants/{id}/rollouts", s.listRollouts)
	mux.HandleFunc("GET /api/rollouts", s.listRollouts)
	mux.HandleFunc("GET /api/rollouts/{id}", s.getRollout)
	mux.HandleFunc("POST /api/rollouts/{id}/pause", s.rolloutControl("pause"))
	mux.HandleFunc("POST /api/rollouts/{id}/resume", s.rolloutControl("resume"))
	mux.HandleFunc("POST /api/rollouts/{id}/cancel", s.rolloutControl("cancel"))
	mux.HandleFunc("POST /api/rollouts/{id}/approve", s.rolloutControl("approve"))
	mux.HandleFunc("GET /api/runs", s.runs)
	mux.HandleFunc("GET /api/runs/{id}", s.run)

	sub, _ := fs.Sub(webFS, "web")
	mux.Handle("/", http.FileServer(http.FS(sub)))

	var h http.Handler = mux
	if s.Auth != nil {
		h = s.Auth.Middleware(h)
	}
	h = s.originGuard(h)
	return logging(h)
}

// nowFn is the clock the API uses; tests may replace it.
var nowFn = time.Now

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			fmt.Printf("%s %s %s\n", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
		}
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func body[T any](r *http.Request) (T, error) {
	var v T
	err := json.NewDecoder(r.Body).Decode(&v)
	return v, err
}

// actor is who a change is recorded against. The signed-in session is the
// truth; a header is only trusted when sign-in did not happen in this process,
// because a client could otherwise set it themselves.
func actor(r *http.Request) string {
	if u := auth.UserFrom(r.Context()); u != nil && u.UPN != "" {
		return u.UPN
	}
	// Client-supplied identity headers are never trusted here: the auth
	// middleware already decided who this is, and anything it did not vouch for
	// is recorded as "local".
	return "local"
}

// ---- handlers ----

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	signInActive, signInReason := false, "sign-in package not wired"
	if s.Auth != nil {
		signInActive, signInReason = s.Auth.Enabled(), s.Auth.Reason()
	}
	gate := "anyone in the tenant"
	switch {
	case len(s.Cfg.AllowedUsers) > 0:
		gate = fmt.Sprintf("%d named users", len(s.Cfg.AllowedUsers))
	case s.Cfg.AllowedGroup != "":
		gate = "members of one group"
	}
	writeJSON(w, 200, map[string]any{
		"signInActive":    signInActive,
		"signInReason":    signInReason,
		"accessGate":      gate,
		"user":            auth.UserFrom(r.Context()),
		"templates":       s.Cat.Len(),
		"placeholders":    s.Cat.Placeholders(),
		"readOnly":        s.Cfg.ReadOnly,
		"credentialsSet":  s.Cfg.ClientID != "" && s.Cfg.ClientSecret != "",
		"clientId":        s.Cfg.ClientID,
		"snapshotEvery":   s.Cfg.SnapshotCron,
		"reportOnlyHours": s.Cfg.ReportOnlyHours,
		"actor":           actor(r),
	})
}

// templateView adds what a template actually does, and any mismatch between
// its name and its behavior, to the catalog entry.
type templateView struct {
	catalog.Template
	Does     string   `json:"does,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

func (s *Server) templates(w http.ResponseWriter, r *http.Request) {
	out := make([]templateView, 0, s.Cat.Len())
	for _, t := range s.Cat.All() {
		v := templateView{Template: t}
		if t.Kind == catalog.KindConditionalAccess {
			if sh, err := equiv.Parse(t.Body); err == nil {
				v.Does = equiv.Describe(sh)
				v.Warnings = equiv.AuditName(sh)
			}
		}
		out = append(out, v)
	}
	writeJSON(w, 200, out)
}

func (s *Server) template(w http.ResponseWriter, r *http.Request) {
	t := s.Cat.Get(r.PathValue("id"))
	if t == nil {
		fail(w, 404, fmt.Errorf("no such template"))
		return
	}
	writeJSON(w, 200, map[string]any{"template": t, "body": json.RawMessage(t.Body)})
}

func (s *Server) listTenants(w http.ResponseWriter, r *http.Request) {
	ts, err := s.Store.Tenants()
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, ts)
}

func (s *Server) addTenant(w http.ResponseWriter, r *http.Request) {
	t, err := body[store.Tenant](r)
	if err != nil {
		fail(w, 400, err)
		return
	}
	if strings.TrimSpace(t.ID) == "" {
		fail(w, 400, fmt.Errorf("a tenant id or domain is required"))
		return
	}
	if t.Name == "" {
		t.Name = t.ID
	}
	if t.Status == "" {
		t.Status = "pending"
	}
	if err := s.Store.UpsertTenant(t); err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 201, t)
}

func (s *Server) deleteTenant(w http.ResponseWriter, r *http.Request) {
	if err := s.Store.DeleteTenant(r.PathValue("id")); err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "removed from the console; nothing in the tenant was changed"})
}

func (s *Server) probeTenant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	name, err := s.Engine.Reader(id).Probe(r.Context())
	if err != nil {
		_ = s.Store.UpsertTenant(store.Tenant{ID: id, Name: id, Status: "unreachable"})
		fail(w, 502, err)
		return
	}
	t := store.Tenant{ID: id, Name: name, Status: "connected", LastSeenAt: time.Now().UTC().Format(time.RFC3339)}
	_ = s.Store.UpsertTenant(t)
	writeJSON(w, 200, t)
}

func (s *Server) snapshot(w http.ResponseWriter, r *http.Request) {
	res, err := s.Engine.Snapshot(r.Context(), r.PathValue("id"), "manual", actor(r))
	if err != nil {
		fail(w, 502, err)
		return
	}
	writeJSON(w, 200, res)
}

type compareReq struct {
	Tokens map[string]string `json:"tokens"`
	State  string            `json:"state"`
	// Baseline picks what to assess against: empty for the House standard, or
	// the id of a library from GET /api/assessment/baselines.
	Baseline string `json:"baseline"`
}

func (s *Server) compare(w http.ResponseWriter, r *http.Request) {
	req, _ := body[compareReq](r)
	if req.Baseline != "" && !s.knownBaseline(req.Baseline) {
		fail(w, 400, fmt.Errorf("unknown baseline %q; see /api/assessment/baselines", req.Baseline))
		return
	}
	res, err := s.Engine.CompareAgainst(r.Context(), r.PathValue("id"), req.Tokens, req.State, req.Baseline)
	if err != nil {
		fail(w, 502, err)
		return
	}
	writeJSON(w, 200, res)
}

type baselineChoice struct {
	ID    string `json:"id"` // empty is the House standard
	Label string `json:"label"`
	Count int    `json:"count"`
}

// assessmentBaselines lists what a client can be assessed against: the House
// standard and every imported library.
func (s *Server) assessmentBaselines(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.baselineChoices())
}

func (s *Server) baselineChoices() []baselineChoice {
	std, libs := 0, map[string]int{}
	for _, t := range s.Cat.All() {
		switch {
		case catalog.IsLibrary(t.Category):
			libs[t.Category]++
		case t.Category != "microsoft" && t.Category != "praxis":
			std++
		}
	}
	out := []baselineChoice{{ID: "", Label: "House standard", Count: std}}
	names := make([]string, 0, len(libs))
	for k := range libs {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		label := "Open Intune Baseline: " + strings.TrimPrefix(k, "oib-")
		if strings.HasPrefix(k, "pack-") {
			label = "House pack: " + strings.TrimPrefix(k, "pack-")
		}
		out = append(out, baselineChoice{ID: k, Label: label, Count: libs[k]})
	}
	return out
}

func (s *Server) knownBaseline(id string) bool {
	for _, c := range s.baselineChoices() {
		if c.ID == id {
			return true
		}
	}
	return false
}

func (s *Server) scoreTenant(w http.ResponseWriter, r *http.Request) {
	req, _ := body[compareReq](r)
	tenantID := r.PathValue("id")

	// Microsoft Secure Score needs no mapping from us, so it is the one framework
	// figure that cannot be wrong because of a typo on our side. It is also a
	// separate set of Graph calls, so it runs alongside the tenant read rather
	// than after it. A tenant without it is reported, not fatal.
	var (
		secure    *benchmark.SecureScore
		secureErr string
		wg        sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		ss, err := benchmark.FetchSecureScoreCached(r.Context(), s.Engine.Reader(tenantID), s.profileCache(tenantID))
		if err != nil {
			secureErr = err.Error()
			return
		}
		secure = ss
	}()

	// Microsoft's baselines are compared against every live settings catalog
	// policy, whatever it is called, because the comparison is by setting id.
	var (
		msResults []baseline.Result
		msErr     string
		overlaps  []baseline.Overlap
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		bls, err := s.baselines(r.Context(), tenantID)
		if err != nil {
			msErr = err.Error()
			return
		}
		live, err := s.Engine.Reader(tenantID).List(r.Context(), "/beta/deviceManagement/configurationPolicies?$expand=settings")
		if err != nil {
			msErr = err.Error()
			return
		}
		observed := map[string][]baseline.Observed{}
		for _, p := range live {
			b, _ := json.Marshal(p)
			name, _ := p["name"].(string)
			_ = baseline.Flatten(name, b, observed)
		}
		for _, bl := range bls {
			msResults = append(msResults, baseline.Compare(bl, observed))
		}
		overlaps = baseline.Overlaps(observed, bls)
	}()

	// Microsoft's Conditional Access templates against the tenant's live
	// policies, matched by behavior like everything else.
	var (
		msCA   []mstemplates.Row
		msCAEr string
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		ms := s.msTemplates()
		if len(ms) == 0 {
			msCAEr = "Microsoft's Conditional Access templates have not been fetched yet"
			return
		}
		live, err := s.Engine.Reader(tenantID).List(r.Context(), "/v1.0/identity/conditionalAccess/policies")
		if err != nil {
			msCAEr = err.Error()
			return
		}
		var cands []mstemplates.Candidate
		for _, p := range live {
			b, _ := json.Marshal(p)
			name, _ := p["displayName"].(string)
			state, _ := p["state"].(string)
			cands = append(cands, mstemplates.Candidate{Name: name, Body: b, State: state})
		}
		msCA = mstemplates.Compare(ms, cands)
	}()

	cmp, err := s.Engine.Compare(r.Context(), tenantID, req.Tokens, req.State)
	wg.Wait()
	if err != nil {
		fail(w, 502, err)
		return
	}

	writeJSON(w, 200, map[string]any{
		"score":              score.Score(cmp, s.catalogs(), secure),
		"comparison":         cmp,
		"secureScoreNote":    secureErr,
		"microsoftBaselines": msResults,
		"microsoftNote":      msErr,
		"microsoftCA":        msCA,
		"overlaps":           overlaps,
		"microsoftCANote":    msCAEr,
	})
}

const baselineCacheKey = "microsoft-baselines"
const msTemplatesCacheKey = "microsoft-ca-templates"

// msTemplates returns Microsoft's cached Conditional Access templates.
func (s *Server) msTemplates() []mstemplates.Template {
	cached, err := s.Store.Benchmarks()
	if err != nil {
		return nil
	}
	var out []mstemplates.Template
	if raw, ok := cached[msTemplatesCacheKey]; ok {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

// LoadMSTemplates registers cached Microsoft templates as deployable, so they
// survive a restart without a tenant round trip.
func (s *Server) LoadMSTemplates() int {
	ms := s.msTemplates()
	s.Cat.Replace("microsoft", mstemplates.AsCatalog(ms))
	return len(ms)
}

func (s *Server) refreshMSTemplates(w http.ResponseWriter, r *http.Request) {
	req, _ := body[struct {
		TenantID string `json:"tenantId"`
	}](r)
	if req.TenantID == "" {
		fail(w, 400, fmt.Errorf("pick a connected tenant; Microsoft's templates are read through it"))
		return
	}
	ms, err := mstemplates.Fetch(r.Context(), s.Engine.Reader(req.TenantID))
	if err != nil {
		fail(w, 502, err)
		return
	}
	raw, _ := json.Marshal(ms)
	if err := s.Store.SaveBenchmark(msTemplatesCacheKey, fmt.Sprint(len(ms)), raw); err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"templates": s.LoadMSTemplates()})
}

// compareMSTemplates measures the House Conditional Access templates against
// Microsoft's, by behavior, with no tenant involved.
func (s *Server) compareMSTemplates(w http.ResponseWriter, r *http.Request) {
	ms := s.msTemplates()
	if len(ms) == 0 {
		fail(w, 409, fmt.Errorf("Microsoft's Conditional Access templates have not been fetched yet"))
		return
	}
	var cands []mstemplates.Candidate
	for _, t := range s.Cat.All() {
		if t.Kind != catalog.KindConditionalAccess || t.Category == "microsoft" {
			continue
		}
		cands = append(cands, mstemplates.Candidate{Name: t.Name, Body: t.Body, State: "enabled"})
	}
	writeJSON(w, 200, mstemplates.Compare(ms, cands))
}

// baselines returns Microsoft's baselines from the cache, fetching them through
// the given tenant the first time. They are the same in every tenant.
func (s *Server) baselines(ctx context.Context, tenantID string) ([]baseline.Baseline, error) {
	if cached, err := s.Store.Benchmarks(); err == nil {
		if raw, ok := cached[baselineCacheKey]; ok {
			var out []baseline.Baseline
			if json.Unmarshal(raw, &out) == nil && len(out) > 0 {
				return out, nil
			}
		}
	}
	if tenantID == "" {
		return nil, fmt.Errorf("Microsoft baselines not fetched yet; connect a tenant and press REFRESH")
	}
	return s.fetchBaselines(ctx, tenantID)
}

func (s *Server) fetchBaselines(ctx context.Context, tenantID string) ([]baseline.Baseline, error) {
	bls, err := baseline.Fetch(ctx, s.Engine.Reader(tenantID))
	if err != nil {
		return nil, err
	}
	if raw, err := json.Marshal(bls); err == nil {
		version := ""
		for _, b := range bls {
			version += b.Version + ";"
		}
		_ = s.Store.SaveBenchmark(baselineCacheKey, version, raw)
	}
	return bls, nil
}

func (s *Server) listBaselines(w http.ResponseWriter, r *http.Request) {
	bls, err := s.baselines(r.Context(), "")
	if err != nil {
		writeJSON(w, 200, map[string]any{"baselines": []any{}, "note": err.Error()})
		return
	}
	out := []map[string]any{}
	for _, b := range bls {
		out = append(out, map[string]any{"id": b.ID, "name": b.Name, "version": b.Version, "settings": len(b.Recs), "fetchError": b.FetchError})
	}
	writeJSON(w, 200, map[string]any{"baselines": out})
}

func (s *Server) refreshBaselines(w http.ResponseWriter, r *http.Request) {
	req, _ := body[struct {
		TenantID string `json:"tenantId"`
	}](r)
	if req.TenantID == "" {
		fail(w, 400, fmt.Errorf("pick a connected tenant; Microsoft's baselines are read through it"))
		return
	}
	bls, err := s.fetchBaselines(r.Context(), req.TenantID)
	if err != nil {
		fail(w, 502, err)
		return
	}
	writeJSON(w, 200, map[string]any{"baselines": len(bls)})
}

// whatIf scores a template set as if a tenant had deployed and enforced all of
// it, so the House, Microsoft and Praxis sets can be compared against CIS and
// CISA before any of them touches a client.
func (s *Server) whatIf(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{}
	sets := map[string]func(catalog.Template) bool{
		"house": func(t catalog.Template) bool {
			return t.Category == "conditional-access" || t.Category == "defender" || t.Category == "intune"
		},
		"praxis":    func(t catalog.Template) bool { return t.Category == "praxis" },
		"microsoft": func(t catalog.Template) bool { return t.Category == "microsoft" },
	}
	all := s.Cat.All()
	for name, in := range sets {
		// Credit is by behavior, as in tenant scoring: a set meets a control when
		// one of its policies does what a mapped template does, whatever it is
		// called. Otherwise a set with no mapping entries scores zero regardless
		// of what it actually does.
		var members []*equiv.Shape
		cmp := &engine.CompareResult{}
		for _, t := range all {
			if !in(t) {
				continue
			}
			cmp.Items = append(cmp.Items, engine.TemplateStatus{Template: t, State: "matches", LiveState: "enabled"})
			if t.Kind == catalog.KindConditionalAccess {
				if sh, err := equiv.Parse(t.Body); err == nil {
					members = append(members, sh)
				}
			}
		}
		for _, t := range all {
			if in(t) || t.Kind != catalog.KindConditionalAccess || !score.Mapped(t.ID) {
				continue
			}
			ts, err := equiv.Parse(t.Body)
			if err != nil {
				continue
			}
			for _, m := range members {
				if v := equiv.Covers(m, ts); v.Covers {
					cmp.Items = append(cmp.Items, engine.TemplateStatus{Template: t, State: "equivalent", LiveState: "enabled", Exact: v.Exact})
					break
				}
			}
		}
		sc := score.Score(cmp, s.catalogs(), nil)
		fw := map[string]any{}
		for _, f := range sc.Frameworks {
			fw[f.Framework] = map[string]any{"met": f.Met, "partial": f.Partial, "total": f.Total, "percent": f.Percent}
		}
		n := 0
		for _, t := range all {
			if in(t) {
				n++
			}
		}
		out[name] = map[string]any{"templates": n, "frameworks": fw}
	}
	writeJSON(w, 200, out)
}

func (s *Server) praxisProvenance(w http.ResponseWriter, r *http.Request) {
	p, err := praxisprov.Load()
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, p)
}

// templateOverlaps finds settings two House templates both configure. Deployed
// together, those templates fight over the setting.
func (s *Server) templateOverlaps(w http.ResponseWriter, r *http.Request) {
	observed := map[string][]baseline.Observed{}
	for _, t := range s.Cat.All() {
		if t.Kind == catalog.KindConfigPolicy && !catalog.IsLibrary(t.Category) {
			_ = baseline.Flatten(t.Name, t.Body, observed)
		}
	}
	bls, _ := s.baselines(r.Context(), "")
	writeJSON(w, 200, baseline.Overlaps(observed, bls))
}

// baselineTemplateAudit measures the Defender and Intune templates themselves
// against Microsoft's baselines. It needs no tenant: it answers where the House
// baseline disagrees with Microsoft before anything is deployed.
func (s *Server) baselineTemplateAudit(w http.ResponseWriter, r *http.Request) {
	bls, err := s.baselines(r.Context(), "")
	if err != nil {
		fail(w, 409, err)
		return
	}
	observed := map[string][]baseline.Observed{}
	for _, t := range s.Cat.All() {
		if t.Kind != catalog.KindConfigPolicy || catalog.IsLibrary(t.Category) {
			continue
		}
		_ = baseline.Flatten(t.Name, t.Body, observed)
	}
	var out []baseline.Result
	for _, b := range bls {
		out = append(out, baseline.Compare(b, observed))
	}
	writeJSON(w, 200, out)
}

// profileCache persists the Secure Score control profiles per tenant, reusing
// the benchmark cache table. They are descriptions of Microsoft's controls, not
// tenant data, but they are fetched per tenant so they are keyed that way.
type profileCache struct {
	store  *store.Store
	tenant string
}

func (s *Server) profileCache(tenantID string) benchmark.ProfileCache {
	return &profileCache{store: s.Store, tenant: tenantID}
}

func (p *profileCache) key() string { return "securescore-profiles:" + p.tenant }

func (p *profileCache) Get() ([]map[string]any, bool) {
	cached, err := p.store.Benchmarks()
	if err != nil {
		return nil, false
	}
	raw, ok := cached[p.key()]
	if !ok {
		return nil, false
	}
	var profiles []map[string]any
	if err := json.Unmarshal(raw, &profiles); err != nil || len(profiles) == 0 {
		return nil, false
	}
	return profiles, true
}

func (p *profileCache) Put(profiles []map[string]any) {
	if len(profiles) == 0 {
		return
	}
	if raw, err := json.Marshal(profiles); err == nil {
		_ = p.store.SaveBenchmark(p.key(), "live", raw)
	}
}

// catalogs reads the cached framework catalogs. A framework that has never been
// fetched simply does not appear, and the UI says so rather than inventing one.
func (s *Server) catalogs() map[string]*benchmark.Catalog {
	out := map[string]*benchmark.Catalog{}
	cached, err := s.Store.Benchmarks()
	if err != nil {
		return out
	}
	for source, raw := range cached {
		if c, err := benchmark.Unmarshal(raw); err == nil {
			out[source] = c
		}
	}
	return out
}

func (s *Server) benchmarks(w http.ResponseWriter, r *http.Request) {
	catalogs := s.catalogs()
	summary := map[string]any{}
	for name, c := range catalogs {
		summary[name] = map[string]any{
			"label":   c.Label,
			"version": c.Version, "fetchedAt": c.FetchedAt, "controls": len(c.Controls),
			"url": c.URL, "notes": c.Notes,
		}
	}
	writeJSON(w, 200, map[string]any{
		"cached":  summary,
		"mapping": score.MappingSummary(catalogs),
		"cisDir":  s.Cfg.CISDir,
		"notFetchable": map[string]string{
			"cis": "CIS publishes free PDFs under CC BY-NC-SA 4.0, but each download goes through a sign-up form on CIS's site, so the console cannot fetch them itself. Download them once into a folder and press IMPORT CIS PDFS; the console reads them and keeps the parsed catalog in its own database. The NC (non-commercial) term matters for client reports: cite CIS control ids and link to CIS rather than reproducing their text in a paid deliverable.",
		},
	})
}

func (s *Server) importCIS(w http.ResponseWriter, r *http.Request) {
	req, _ := body[struct {
		Dir string `json:"dir"`
	}](r)
	dir := strings.TrimSpace(req.Dir)
	if dir == "" {
		dir = s.Cfg.CISDir
	}
	if dir == "" {
		fail(w, 400, fmt.Errorf("no folder given and PC_CIS_DIR is not set"))
		return
	}
	cats, err := benchmark.ImportCIS(r.Context(), dir)
	if err != nil {
		fail(w, 502, err)
		return
	}
	var out []map[string]any
	for _, c := range cats {
		raw, err := c.MarshalCache()
		if err != nil {
			fail(w, 500, err)
			return
		}
		if err := s.Store.SaveBenchmark(c.Source, c.Version, raw); err != nil {
			fail(w, 500, err)
			return
		}
		out = append(out, map[string]any{"source": c.Source, "label": c.Label, "version": c.Version, "controls": len(c.Controls)})
	}
	writeJSON(w, 200, map[string]any{"imported": out, "mapping": score.MappingSummary(s.catalogs())})
}

func (s *Server) refreshBenchmarks(w http.ResponseWriter, r *http.Request) {
	cat, err := benchmark.FetchScuba(r.Context(), nil)
	if err != nil {
		fail(w, 502, err)
		return
	}
	raw, err := cat.MarshalCache()
	if err != nil {
		fail(w, 500, err)
		return
	}
	if err := s.Store.SaveBenchmark("scuba", cat.Version, raw); err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{
		"source": "scuba", "version": cat.Version, "controls": len(cat.Controls),
		"mapping": score.MappingSummary(map[string]*benchmark.Catalog{"scuba": cat}),
	})
}

func (s *Server) deploy(w http.ResponseWriter, r *http.Request) {
	req, err := body[engine.DeployRequest](r)
	if err != nil {
		fail(w, 400, err)
		return
	}
	req.TenantID = r.PathValue("id")
	req.Actor = actor(r)
	if !req.Preview && s.Cfg.ReadOnly {
		fail(w, 403, fmt.Errorf("console is in read-only mode; preview works, writes do not"))
		return
	}
	res, err := s.Engine.Deploy(r.Context(), req)
	if err != nil {
		fail(w, 502, err)
		return
	}
	writeJSON(w, 200, res)
}

type revertReq struct {
	Kind     string `json:"kind"`
	ObjectID string `json:"objectId"`
	Version  int    `json:"version"`
}

func (s *Server) revert(w http.ResponseWriter, r *http.Request) {
	req, err := body[revertReq](r)
	if err != nil {
		fail(w, 400, err)
		return
	}
	item, err := s.Engine.Revert(r.Context(), r.PathValue("id"), catalog.Kind(req.Kind), req.ObjectID, req.Version, actor(r))
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": err.Error(), "item": item})
		return
	}
	writeJSON(w, 200, item)
}

type modifyReq struct {
	Kind     string          `json:"kind"`
	ObjectID string          `json:"objectId"`
	Body     json.RawMessage `json:"body"`
	Note     string          `json:"note"`
}

func (s *Server) modify(w http.ResponseWriter, r *http.Request) {
	req, err := body[modifyReq](r)
	if err != nil {
		fail(w, 400, err)
		return
	}
	item, err := s.Engine.Write(r.Context(), r.PathValue("id"), catalog.Kind(req.Kind), req.ObjectID, req.Body, "modify", actor(r), req.Note)
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": err.Error(), "item": item})
		return
	}
	writeJSON(w, 200, item)
}

type enforceReq struct {
	ObjectID string `json:"objectId"`
	Override string `json:"override"` // reason, required only when enforcing early
}

func (s *Server) enforce(w http.ResponseWriter, r *http.Request) {
	if s.Cfg.ReadOnly {
		fail(w, 403, fmt.Errorf("console is in read-only mode"))
		return
	}
	req, err := body[enforceReq](r)
	if err != nil {
		fail(w, 400, err)
		return
	}
	res, err := s.Engine.Enforce(r.Context(), r.PathValue("id"), req.ObjectID, s.Cfg.ReportOnlyHours, req.Override, actor(r))
	if err != nil {
		fail(w, 409, err)
		return
	}
	writeJSON(w, 200, res)
}

type widenReq struct {
	Kind       string `json:"kind"`
	ObjectID   string `json:"objectId"`
	PilotGroup string `json:"pilotGroupId"`
}

func (s *Server) widen(w http.ResponseWriter, r *http.Request) {
	if s.Cfg.ReadOnly {
		fail(w, 403, fmt.Errorf("console is in read-only mode"))
		return
	}
	req, err := body[widenReq](r)
	if err != nil {
		fail(w, 400, err)
		return
	}
	res, err := s.Engine.Widen(r.Context(), r.PathValue("id"), catalog.Kind(req.Kind), req.ObjectID, req.PilotGroup, actor(r))
	if err != nil {
		fail(w, 409, err)
		return
	}
	writeJSON(w, 200, res)
}

// reportOnly lists the tenant's report-only Conditional Access policies with
// how long each has been observing, from the console's own history.
func (s *Server) reportOnly(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("id")
	objs, err := s.Store.LatestObjects(tenantID)
	if err != nil {
		fail(w, 500, err)
		return
	}
	type row struct {
		ObjectID string  `json:"objectId"`
		Name     string  `json:"name"`
		Since    string  `json:"since"`
		Hours    float64 `json:"hours"`
		Ready    bool    `json:"ready"`
	}
	out := []row{}
	for _, o := range objs {
		if o.Kind != string(catalog.KindConditionalAccess) || o.Deleted {
			continue
		}
		since, ro, err := s.Engine.ReportOnlySince(tenantID, o.ObjectID)
		if err != nil || !ro {
			continue
		}
		h := time.Since(since).Hours()
		out = append(out, row{ObjectID: o.ObjectID, Name: o.Name, Since: since.Format(time.RFC3339), Hours: h, Ready: h >= float64(s.Cfg.ReportOnlyHours)})
	}
	writeJSON(w, 200, map[string]any{"minimumHours": s.Cfg.ReportOnlyHours, "policies": out})
}

func (s *Server) objects(w http.ResponseWriter, r *http.Request) {
	objs, err := s.Store.LatestObjects(r.PathValue("id"))
	if err != nil {
		fail(w, 500, err)
		return
	}
	for i := range objs {
		objs[i].Body = nil // the list view does not need every full policy document
	}
	writeJSON(w, 200, objs)
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	hist, err := s.Store.History(r.PathValue("id"), q.Get("kind"), q.Get("objectId"))
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, hist)
}

func (s *Server) version(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	n, _ := strconv.Atoi(q.Get("version"))
	v, err := s.Store.VersionBody(r.PathValue("id"), q.Get("kind"), q.Get("objectId"), n)
	if err != nil {
		fail(w, 500, err)
		return
	}
	if v == nil {
		fail(w, 404, fmt.Errorf("no such version"))
		return
	}
	writeJSON(w, 200, v)
}

// versionDiff answers "what changed between these two points in time", which is
// the question a tech actually has when a client says something broke yesterday.
func (s *Server) versionDiff(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	from, _ := strconv.Atoi(q.Get("from"))
	to, _ := strconv.Atoi(q.Get("to"))
	a, err := s.Store.VersionBody(r.PathValue("id"), q.Get("kind"), q.Get("objectId"), from)
	if err != nil || a == nil {
		fail(w, 404, fmt.Errorf("version %d not found", from))
		return
	}
	b, err := s.Store.VersionBody(r.PathValue("id"), q.Get("kind"), q.Get("objectId"), to)
	if err != nil || b == nil {
		fail(w, 404, fmt.Errorf("version %d not found", to))
		return
	}
	changes, err := diff.Compare(a.Body, b.Body)
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"from": a, "to": b, "changes": changes})
}

func (s *Server) runs(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rs, err := s.Store.Runs(r.URL.Query().Get("tenantId"), limit)
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, rs)
}

func (s *Server) run(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	items, err := s.Store.RunItems(id)
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, items)
}

var _ = context.Background

// originGuard refuses state-changing requests a browser sent from another site.
// A request with an Origin must match this console's own host. A request with
// no Origin (curl, scripts) is allowed unless the browser says it is cross-site.
func (s *Server) originGuard(next http.Handler) http.Handler {
	own := map[string]bool{}
	if u, err := url.Parse(s.Cfg.PublicURL); err == nil && u.Host != "" {
		own[strings.ToLower(u.Host)] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if o := r.Header.Get("Origin"); o != "" {
			u, err := url.Parse(o)
			host := ""
			if err == nil {
				host = strings.ToLower(u.Host)
			}
			if host == "" || (!own[host] && host != strings.ToLower(r.Host)) {
				http.Error(w, `{"error":"cross-site request refused"}`, http.StatusForbidden)
				return
			}
		} else if sf := r.Header.Get("Sec-Fetch-Site"); sf != "" && sf != "same-origin" && sf != "none" {
			http.Error(w, `{"error":"cross-site request refused"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }
