package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anthonyonazure/policy-console/internal/config"
	"github.com/anthonyonazure/policy-console/internal/consent"
	"github.com/anthonyonazure/policy-console/internal/store"
)

const (
	cTenant = "11111111-1111-1111-1111-111111111111"
	cApp    = "22222222-2222-2222-2222-222222222222"
)

type tokenFn func(string) (string, error)

func (f tokenFn) Token(_ context.Context, t string) (string, error) { return f(t) }

func jwtFor(tid string, wids ...string) string {
	b, _ := json.Marshal(map[string]any{"tid": tid, "wids": wids})
	return "h." + base64.RawURLEncoding.EncodeToString(b) + ".s"
}

// dirAPI is a tiny client directory.
type dirAPI struct {
	graph, app *consent.ServicePrincipal
	assigned   map[string]bool
}

func newDir() *dirAPI {
	d := &dirAPI{assigned: map[string]bool{}, graph: &consent.ServicePrincipal{ID: "g", AppID: consent.GraphAppID}}
	for _, g := range consent.Manifest(consent.ProfileWrite) {
		d.graph.AppRoles = append(d.graph.AppRoles, consent.AppRole{ID: "r-" + g.Permission, Value: g.Permission, IsEnabled: true, AllowedMemberTypes: []string{"Application"}})
	}
	return d
}
func (d *dirAPI) FindServicePrincipal(_ context.Context, id string) (*consent.ServicePrincipal, error) {
	if id == consent.GraphAppID {
		return d.graph, nil
	}
	return d.app, nil
}
func (d *dirAPI) CreateServicePrincipal(_ context.Context, id string) (*consent.ServicePrincipal, error) {
	d.app = &consent.ServicePrincipal{ID: "a", AppID: id}
	return d.app, nil
}
func (d *dirAPI) Assignments(context.Context, string) ([]consent.Assignment, error) {
	var out []consent.Assignment
	for id := range d.assigned {
		out = append(out, consent.Assignment{AppRoleID: id, ResourceID: "g"})
	}
	return out, nil
}
func (d *dirAPI) Assign(_ context.Context, _, _, role string) error {
	d.assigned[role] = true
	return nil
}

func consentServer(t *testing.T, readOnly bool, tok tokenFn) (*Server, *dirAPI, http.Handler) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	_ = db.UpsertTenant(store.Tenant{ID: cTenant, Name: "Acme", Status: "connected"})
	d := newDir()
	s := &Server{Cfg: config.Config{ClientID: cApp, ReadOnly: readOnly}, Store: db,
		ConsentTokens: tok, ConsentAPI: func(string) consent.API { return d }}
	return s, d, s.Handler()
}

func post(h http.Handler, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func goodToken(string) (string, error) {
	return jwtFor(cTenant, "62e90394-69f5-4237-9190-012177145e10"), nil
}

func TestConsentPreviewThenConfirmGrantsAndRemembers(t *testing.T) {
	s, d, h := consentServer(t, false, goodToken)
	w := post(h, "/api/tenants/"+cTenant+"/consent/plan", `{"profile":"write"}`)
	if w.Code != 200 {
		t.Fatalf("plan: %d %s", w.Code, w.Body)
	}
	var plan consent.Plan
	_ = json.Unmarshal(w.Body.Bytes(), &plan)
	if plan.Missing == 0 || len(d.assigned) != 0 {
		t.Fatalf("a preview must grant nothing: missing=%d granted=%d", plan.Missing, len(d.assigned))
	}
	w = post(h, "/api/tenants/"+cTenant+"/consent/apply", `{"profile":"write","hash":"`+plan.Hash+`","confirm":true}`)
	if w.Code != 200 {
		t.Fatalf("apply: %d %s", w.Code, w.Body)
	}
	if len(d.assigned) != plan.Missing {
		t.Fatalf("granted %d of %d", len(d.assigned), plan.Missing)
	}
	have, _ := s.Store.Consents(cTenant, "write")
	if len(have) != plan.Missing {
		t.Fatalf("remembered %d", len(have))
	}
	runs, _ := s.Store.Runs(cTenant, 5)
	if len(runs) == 0 || runs[0].Action != "consent" {
		t.Fatalf("a grant must be recorded as a run: %+v", runs)
	}
}

func TestConsentApplyNeedsConfirmAndRespectsReadOnly(t *testing.T) {
	_, d, h := consentServer(t, false, goodToken)
	if w := post(h, "/api/tenants/"+cTenant+"/consent/apply", `{"profile":"write","hash":"x"}`); w.Code != 400 {
		t.Fatalf("no confirm: %d", w.Code)
	}
	if len(d.assigned) != 0 {
		t.Fatal("granted without confirmation")
	}
	_, d2, h2 := consentServer(t, true, goodToken)
	if w := post(h2, "/api/tenants/"+cTenant+"/consent/apply", `{"profile":"write","hash":"x","confirm":true}`); w.Code != 403 {
		t.Fatalf("read-only mode must refuse: %d", w.Code)
	}
	if len(d2.assigned) != 0 {
		t.Fatal("granted in read-only mode")
	}
}

func TestConsentRefusesWrongTenantAndMissingRole(t *testing.T) {
	_, _, h := consentServer(t, false, func(string) (string, error) {
		return jwtFor("99999999-9999-9999-9999-999999999999", "62e90394-69f5-4237-9190-012177145e10"), nil
	})
	if w := post(h, "/api/tenants/"+cTenant+"/consent/plan", `{"profile":"write"}`); w.Code != 412 || !strings.Contains(w.Body.String(), "different client") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	_, _, h = consentServer(t, false, func(string) (string, error) { return jwtFor(cTenant, "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"), nil })
	if w := post(h, "/api/tenants/"+cTenant+"/consent/plan", `{"profile":"write"}`); w.Code != 412 || !strings.Contains(w.Body.String(), "Privileged Role Administrator") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestConsentReadProfileNeedsItsOwnApplication(t *testing.T) {
	_, _, h := consentServer(t, false, goodToken)
	w := post(h, "/api/tenants/"+cTenant+"/consent/plan", `{"profile":"read"}`)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "READ_CLIENT_ID") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestConsentStatusShowsPerKind(t *testing.T) {
	s, _, h := consentServer(t, false, goodToken)
	_ = s.Store.SaveConsents(cTenant, "write", map[string]bool{"Organization.Read.All": true}, []string{"Organization.Read.All"}, timeNow())
	req := httptest.NewRequest("GET", "/api/tenants/"+cTenant+"/consent", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"kind":"tenant","state":"granted"`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}
