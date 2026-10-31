package consent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	tenant = "11111111-1111-1111-1111-111111111111"
	appID  = "22222222-2222-2222-2222-222222222222"
)

// fakeAPI behaves like a client tenant's directory.
type fakeAPI struct {
	graphSP   *ServicePrincipal
	appSP     *ServicePrincipal
	assigned  map[string]bool // role id
	silent    bool            // Assign returns success but records nothing (Microsoft's reported failure mode)
	failRole  string
	assignErr map[string][]error // role id -> errors to return before succeeding
	created   int
}

func newFake(perms ...string) *fakeAPI {
	f := &fakeAPI{assigned: map[string]bool{}, assignErr: map[string][]error{}}
	f.graphSP = &ServicePrincipal{ID: "graph-sp", AppID: GraphAppID}
	for _, p := range perms {
		f.graphSP.AppRoles = append(f.graphSP.AppRoles, AppRole{ID: "role-" + p, Value: p, IsEnabled: true, AllowedMemberTypes: []string{"Application"}})
	}
	return f
}

func allPerms(profile string) []string {
	var out []string
	for _, g := range Manifest(profile) {
		out = append(out, g.Permission)
	}
	return out
}

func (f *fakeAPI) FindServicePrincipal(_ context.Context, id string) (*ServicePrincipal, error) {
	if id == GraphAppID {
		return f.graphSP, nil
	}
	return f.appSP, nil
}
func (f *fakeAPI) CreateServicePrincipal(_ context.Context, id string) (*ServicePrincipal, error) {
	f.created++
	f.appSP = &ServicePrincipal{ID: "app-sp", AppID: id}
	return f.appSP, nil
}
func (f *fakeAPI) Assignments(context.Context, string) ([]Assignment, error) {
	var out []Assignment
	for id := range f.assigned {
		out = append(out, Assignment{AppRoleID: id, ResourceID: f.graphSP.ID})
	}
	return out, nil
}
func (f *fakeAPI) Assign(_ context.Context, _, _, roleID string) error {
	if errs := f.assignErr[roleID]; len(errs) > 0 {
		f.assignErr[roleID] = errs[1:]
		return errs[0]
	}
	if !f.silent {
		f.assigned[roleID] = true
	}
	return nil
}

func TestPlanListsExactlyWhatIsMissing(t *testing.T) {
	f := newFake(allPerms(ProfileRead)...)
	f.appSP = &ServicePrincipal{ID: "app-sp", AppID: appID}
	f.assigned["role-Organization.Read.All"] = true
	p, err := BuildPlan(context.Background(), f, tenant, ProfileRead, appID)
	if err != nil {
		t.Fatal(err)
	}
	if !p.HasSP || p.Missing != len(Manifest(ProfileRead))-1 {
		t.Fatalf("missing = %d, has SP = %v", p.Missing, p.HasSP)
	}
}

func TestApplyGrantsCreatesTheApplicationAndVerifies(t *testing.T) {
	f := newFake(allPerms(ProfileWrite)...)
	plan, _ := BuildPlan(context.Background(), f, tenant, ProfileWrite, appID)
	if plan.HasSP {
		t.Fatal("application should not exist yet")
	}
	res, err := Apply(context.Background(), f, plan, func(time.Duration) {})
	if err != nil {
		t.Fatal(err)
	}
	if f.created != 1 || res.Verified.Missing != 0 {
		t.Fatalf("created=%d missing=%d", f.created, res.Verified.Missing)
	}
	// Running it again is a no-op, not a second application.
	plan2, _ := BuildPlan(context.Background(), f, tenant, ProfileWrite, appID)
	if plan2.Missing != 0 {
		t.Fatalf("second plan should be empty: %d", plan2.Missing)
	}
}

func TestSilentSuccessIsCaughtByTheReadBack(t *testing.T) {
	f := newFake(allPerms(ProfileRead)...)
	f.silent = true
	plan, _ := BuildPlan(context.Background(), f, tenant, ProfileRead, appID)
	_, err := Apply(context.Background(), f, plan, func(time.Duration) {})
	if err == nil || !strings.Contains(err.Error(), "still not granted") {
		t.Fatalf("a grant that did nothing must be reported as a failure: %v", err)
	}
}

func TestConfirmationOnlyCoversThePlanThatWasShown(t *testing.T) {
	f := newFake(allPerms(ProfileRead)...)
	f.appSP = &ServicePrincipal{ID: "app-sp", AppID: appID}
	shown, _ := BuildPlan(context.Background(), f, tenant, ProfileRead, appID)
	f.assigned["role-Policy.Read.All"] = true // someone else grants one in between
	_, err := Apply(context.Background(), f, shown, func(time.Duration) {})
	if !errors.Is(err, ErrPlanChanged) {
		t.Fatalf("want ErrPlanChanged, got %v", err)
	}
	if len(f.assigned) != 1 {
		t.Fatal("nothing may be granted after a stale confirmation")
	}
}

func TestAPermissionMicrosoftDoesNotOfferIsNeverGuessed(t *testing.T) {
	perms := allPerms(ProfileRead)
	f := newFake(perms[1:]...) // first permission absent from the client's Graph
	plan, _ := BuildPlan(context.Background(), f, tenant, ProfileRead, appID)
	if len(plan.Unresolved) != 1 || plan.Unresolved[0] != perms[0] {
		t.Fatalf("unresolved = %v", plan.Unresolved)
	}
	if _, err := Apply(context.Background(), f, plan, func(time.Duration) {}); err == nil || len(f.assigned) != 0 {
		t.Fatalf("must refuse and grant nothing: %v, granted %d", err, len(f.assigned))
	}
}

func TestRecentlyCreatedApplicationIsRetriedNotFailed(t *testing.T) {
	f := newFake(allPerms(ProfileRead)...)
	f.assignErr["role-Organization.Read.All"] = []error{&APIError{Status: 400, Body: "does not exist"}, &APIError{Status: 404}}
	plan, _ := BuildPlan(context.Background(), f, tenant, ProfileRead, appID)
	var slept int
	if _, err := Apply(context.Background(), f, plan, func(time.Duration) { slept++ }); err != nil {
		t.Fatal(err)
	}
	if slept != 2 {
		t.Fatalf("slept %d times", slept)
	}
}

func TestAlreadyGrantedConflictCountsAsGranted(t *testing.T) {
	f := newFake(allPerms(ProfileRead)...)
	f.assignErr["role-Policy.Read.All"] = []error{&APIError{Status: 409}}
	f.assigned["role-Policy.Read.All"] = true // it really is there
	plan, _ := BuildPlan(context.Background(), f, tenant, ProfileRead, appID)
	if _, err := Apply(context.Background(), f, plan, func(time.Duration) {}); err != nil {
		t.Fatal(err)
	}
}

func jwt(claims map[string]any) string {
	b, _ := json.Marshal(claims)
	return "h." + base64.RawURLEncoding.EncodeToString(b) + ".s"
}

func TestPreflight(t *testing.T) {
	ok := Claims{TenantID: tenant, Roles: []string{rolePrivilegedRoleAdmin}}
	if err := Preflight(ok, tenant); err != nil {
		t.Fatal(err)
	}
	if err := Preflight(Claims{TenantID: tenant, Roles: []string{roleGlobalAdmin}}, strings.ToUpper(tenant)); err != nil {
		t.Fatalf("global admin and case differences must pass: %v", err)
	}
	if err := Preflight(Claims{TenantID: "other", Roles: []string{roleGlobalAdmin}}, tenant); err == nil {
		t.Fatal("a token for a different client must be refused")
	}
	err := Preflight(Claims{TenantID: tenant, Roles: []string{"9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"}}, tenant) // Application Administrator
	if err == nil || !strings.Contains(err.Error(), "Privileged Role Administrator") {
		t.Fatalf("Application Administrator cannot grant Graph app roles: %v", err)
	}
	c, err := ReadClaims(jwt(map[string]any{"tid": tenant, "wids": []string{roleGlobalAdmin}}))
	if err != nil || c.TenantID != tenant || len(c.Roles) != 1 {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := ReadClaims("not-a-token"); err == nil {
		t.Fatal("garbage token")
	}
}

func TestAzCLIRefusesNonGuidAndNeverUsesAShell(t *testing.T) {
	a := AzCLI{Run: func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("ran with a bad tenant id")
		return nil, nil
	}}
	if _, err := a.Token(context.Background(), "x; rm -rf ~"); err == nil {
		t.Fatal("a non-GUID tenant id must be refused")
	}
	var gotName string
	var gotArgs []string
	a = AzCLI{Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		gotName, gotArgs = name, args
		return []byte("tok\n"), nil
	}}
	tok, err := a.Token(context.Background(), tenant)
	if err != nil || tok != "tok" || gotName != "az" || !contains(gotArgs, tenant) {
		t.Fatalf("%q %v %s %v", tok, err, gotName, gotArgs)
	}
	a = AzCLI{Run: func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("exit 1") }}
	if _, err := a.Token(context.Background(), tenant); err == nil || !strings.Contains(err.Error(), "az login --tenant "+tenant) {
		t.Fatalf("the error must tell the operator what to run: %v", err)
	}
}

func TestHTTPAPIRetriesThrottlingAndSendsTheBearer(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("auth header = %q", r.Header.Get("Authorization"))
		}
		if atomic.AddInt32(&calls, 1) < 3 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(429)
			return
		}
		_, _ = w.Write([]byte(`{"value":[{"id":"sp1","appId":"` + appID + `"}]}`))
	}))
	defer srv.Close()
	var waits []time.Duration
	h := &HTTPAPI{Token: "tok", Base: srv.URL, Sleep: func(d time.Duration) { waits = append(waits, d) }}
	sp, err := h.FindServicePrincipal(context.Background(), appID)
	if err != nil || sp == nil || sp.ID != "sp1" {
		t.Fatalf("%v %v", sp, err)
	}
	if len(waits) != 2 || waits[0] != time.Second {
		t.Fatalf("should honour Retry-After twice: %v", waits)
	}
}

func TestHTTPAPIErrorsCarryTheStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "nope", 403) }))
	defer srv.Close()
	h := &HTTPAPI{Token: "tok", Base: srv.URL}
	err := h.Assign(context.Background(), "a", "b", "c")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 403 {
		t.Fatalf("%v", err)
	}
}

func TestKindStatesLetOneRefusalBlockOnlyThatKind(t *testing.T) {
	granted := map[string]bool{}
	for _, g := range Manifest(ProfileRead) {
		granted[g.Permission] = true
	}
	delete(granted, "SecurityEvents.Read.All")
	for _, ks := range KindStates(ProfileRead, granted) {
		want := "granted"
		if ks.Kind == "score" {
			want = "none"
		}
		if ks.State != want {
			t.Errorf("%s = %s, want %s", ks.Kind, ks.State, want)
		}
	}
}

func TestWriteProfileIncludesReadPermissions(t *testing.T) {
	w := map[string]bool{}
	for _, g := range Manifest(ProfileWrite) {
		w[g.Permission] = true
	}
	for _, g := range Manifest(ProfileRead) {
		if !w[g.Permission] {
			t.Errorf("write profile lacks %s", g.Permission)
		}
	}
	if Manifest("bogus") != nil {
		t.Error("unknown profile must have no manifest")
	}
}

// The standing rule: Partner Center is read only. This package must not even
// contain the address of its API.
func TestPackageNeverReferencesThePartnerCenterAPI(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		if strings.Contains(strings.ToLower(string(b)), "partnercenter") {
			t.Errorf("%s mentions the Partner Center API", f)
		}
	}
	if !strings.HasPrefix(graphBase, "https://graph.microsoft.com/") {
		t.Fatal("base must be Microsoft Graph")
	}
}
