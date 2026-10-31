package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func configured() *Authenticator {
	return New(Config{
		TenantID: "t", ClientID: "c", ClientSecret: "s",
		RedirectURL: "http://localhost:4930/auth/callback", SessionKey: NewSessionKey(),
	})
}

// With sign-in configured, an unauthenticated API call must be refused rather
// than quietly running as nobody.
func TestApiRequiresSession(t *testing.T) {
	a := configured()
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler ran without a session")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/tenants", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestBrowserRequestRedirectsToSignIn(t *testing.T) {
	a := configured()
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("expected a redirect to Entra ID, got %d", rec.Code)
	}
}

// A tampered session must be rejected, not read.
func TestTamperedSessionRejected(t *testing.T) {
	a := configured()
	good := a.sign([]byte(`{"upn":"tech@house","exp":9999999999}`))
	if _, err := a.verify(good); err != nil {
		t.Fatalf("valid session rejected: %v", err)
	}
	if _, err := a.verify(good[:len(good)-2] + "xx"); err == nil {
		t.Fatal("tampered session accepted")
	}
	other := configured()
	if _, err := other.verify(good); err == nil {
		t.Fatal("session signed with a different key accepted")
	}
}

func TestAllowListBlocksOtherUsers(t *testing.T) {
	a := New(Config{AllowedUsers: []string{"tech@example.com"}})
	if err := a.permitted(&User{UPN: "tech@example.com"}); err != nil {
		t.Fatalf("allowed user refused: %v", err)
	}
	if err := a.permitted(&User{UPN: "someone@else.com"}); err == nil {
		t.Fatal("user outside the allow-list was permitted")
	}
}

func TestGroupGate(t *testing.T) {
	a := New(Config{AllowedGroup: "group-1"})
	if err := a.permitted(&User{UPN: "a@b.c", Groups: []string{"group-1"}}); err != nil {
		t.Fatalf("group member refused: %v", err)
	}
	if err := a.permitted(&User{UPN: "a@b.c", Groups: []string{"group-9"}}); err == nil {
		t.Fatal("non-member permitted")
	}
}

// Easy Auth in front of the console must not be second-guessed.
func TestEasyAuthHeaderTrustedWithSecret(t *testing.T) {
	a := New(Config{TenantID: "t", ClientID: "c", ClientSecret: "s", SessionKey: NewSessionKey(), EasyAuthSecret: "k"})
	var seen string
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u := UserFrom(r.Context()); u != nil {
			seen = u.UPN
		}
	}))
	req := httptest.NewRequest("GET", "/api/tenants", nil)
	req.Header.Set("X-Ms-Client-Principal-Name", "tech@example.com")
	req.Header.Set("X-Pc-Easyauth-Secret", "k")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if seen != "tech@example.com" {
		t.Fatalf("Easy Auth identity not used, got %q", seen)
	}
}

func easyAuthReq(secret string) *http.Request {
	r := httptest.NewRequest("GET", "/api/tenants", nil)
	r.Header.Set("X-Ms-Client-Principal-Name", "attacker@evil.test")
	if secret != "" {
		r.Header.Set("X-Pc-Easyauth-Secret", secret)
	}
	return r
}

// A forged header must not sign anyone in when no shared secret is configured.
func TestEasyAuthHeaderIgnoredWithoutSecret(t *testing.T) {
	a := configured()
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("forged header was accepted")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, easyAuthReq(""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestEasyAuthHeaderNeedsMatchingSecret(t *testing.T) {
	a := New(Config{TenantID: "t", ClientID: "c", ClientSecret: "s", SessionKey: NewSessionKey(), EasyAuthSecret: "right"})
	ran := false
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran = true
		if UserFrom(r.Context()).UPN != "attacker@evil.test" {
			t.Fatal("wrong identity")
		}
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, easyAuthReq("wrong"))
	if ran || rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret accepted (ran=%v code=%d)", ran, rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, easyAuthReq("right"))
	if !ran || rec.Code != http.StatusOK {
		t.Fatalf("right secret refused (ran=%v code=%d)", ran, rec.Code)
	}
}

func TestViewerCannotWrite(t *testing.T) {
	a := New(Config{EasyAuthSecret: "k", DeployerUsers: []string{"boss@house"}})
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	do := func(upn, method, path string) int {
		r := httptest.NewRequest(method, path, nil)
		r.Header.Set("X-Ms-Client-Principal-Name", upn)
		r.Header.Set("X-Pc-Easyauth-Secret", "k")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	if c := do("viewer@house", "POST", "/api/tenants/x/deploy"); c != http.StatusForbidden {
		t.Fatalf("viewer deploy: %d", c)
	}
	if c := do("viewer@house", "DELETE", "/api/tenants/x"); c != http.StatusForbidden {
		t.Fatalf("viewer delete: %d", c)
	}
	if c := do("viewer@house", "GET", "/api/tenants"); c != http.StatusOK {
		t.Fatalf("viewer read: %d", c)
	}
	if c := do("viewer@house", "POST", "/api/tenants/x/compare"); c != http.StatusOK {
		t.Fatalf("viewer compare: %d", c)
	}
	if c := do("boss@house", "POST", "/api/tenants/x/deploy"); c != http.StatusOK {
		t.Fatalf("deployer deploy: %d", c)
	}
}
