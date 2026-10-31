// Package auth puts Entra ID sign-in in front of the console so only House
// staff reach it, and records who each change belongs to.
//
// It uses the OpenID Connect authorization code flow with PKCE against the
// console's own single-tenant app registration. The ID token is read straight
// from the token endpoint over TLS as a confidential client, which OpenID
// Connect Core 3.1.3.7 accepts in place of verifying the token signature; that
// avoids hand-rolling JWT crypto for no security gain.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	TenantID       string // the tenant staff sign in from
	ClientID       string // the console's own app registration
	ClientSecret   string
	RedirectURL    string   // must match a redirect URI on that registration
	SessionKey     []byte   // signs the session cookie
	AllowedUsers   []string // optional allow-list of user principal names
	AllowedGroup   string   // optional group object id a user must be in
	Disabled       bool     // local development only
	EasyAuthSecret string   // shared secret proving a request came through the trusted front end
	DeployerUsers  []string
	DeployerGroup  string
	SecureCookie   bool
}

// User is who the console believes is driving it.
type User struct {
	Name    string   `json:"name"`
	UPN     string   `json:"upn"`
	OID     string   `json:"oid"`
	Groups  []string `json:"groups,omitempty"`
	Role    string   `json:"role,omitempty"` // "deployer" or "viewer"; never read from a cookie
	Expires int64    `json:"exp"`
}

const (
	sessionCookie = "pc_session"
	stateCookie   = "pc_state"
	sessionHours  = 10
)

type Authenticator struct {
	cfg  Config
	http *http.Client
}

func New(cfg Config) *Authenticator {
	return &Authenticator{cfg: cfg, http: &http.Client{Timeout: 30 * time.Second}}
}

func (a *Authenticator) Enabled() bool {
	return !a.cfg.Disabled && a.cfg.ClientID != "" && a.cfg.ClientSecret != "" && a.cfg.TenantID != ""
}

// Reason explains, in the operator's terms, why sign-in is not active. An
// empty string means it is.
func (a *Authenticator) Reason() string {
	switch {
	case a.cfg.Disabled:
		return "sign-in switched off with PC_AUTH_DISABLED"
	case a.cfg.TenantID == "":
		return "no PC_TENANT_ID set"
	case a.cfg.ClientID == "":
		return "no PC_WEB_CLIENT_ID set"
	case a.cfg.ClientSecret == "":
		return "no PC_WEB_CLIENT_SECRET set"
	}
	return ""
}

type ctxKey struct{}

func WithUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, ctxKey{}, u)
}

func UserFrom(ctx context.Context) *User {
	u, _ := ctx.Value(ctxKey{}).(*User)
	return u
}

// ---- middleware ----

// Middleware rejects anything without a valid session. Paths under /auth/ and
// the health check stay open, because otherwise sign-in could never start.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/auth/") || r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}

		// Azure App Service Easy Auth terminates sign-in ahead of us. Its header is
		// trusted only when a shared secret is configured and the request proves
		// it came through the front end that holds it. Otherwise the header is a
		// value any caller could have typed, so it is ignored.
		if u := a.easyAuthUser(r); u != nil {
			if err := a.permitted(u); err != nil {
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
			a.serve(next, w, r, u)
			return
		}

		if !a.Enabled() {
			a.serve(next, w, r, &User{UPN: "local", Name: "local (sign-in not configured)"})
			return
		}

		u, err := a.session(r)
		if err != nil {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, `{"error":"not signed in"}`, http.StatusUnauthorized)
				return
			}
			a.startLogin(w, r)
			return
		}
		if err := a.permitted(u); err != nil { // allow-list changes apply to live sessions too
			http.Error(w, `{"error":"not permitted"}`, http.StatusForbidden)
			return
		}
		a.serve(next, w, r, u)
	})
}

// easyAuthUser returns the Easy Auth identity, or nil when the header is absent
// or the shared secret is unset or wrong.
func (a *Authenticator) easyAuthUser(r *http.Request) *User {
	upn := r.Header.Get("X-Ms-Client-Principal-Name")
	if upn == "" || a.cfg.EasyAuthSecret == "" {
		return nil
	}
	got := r.Header.Get("X-Pc-Easyauth-Secret")
	if subtle.ConstantTimeCompare([]byte(got), []byte(a.cfg.EasyAuthSecret)) != 1 {
		return nil
	}
	u := &User{UPN: upn, Name: upn}
	if raw := r.Header.Get("X-Ms-Client-Principal"); raw != "" {
		if b, err := base64.StdEncoding.DecodeString(raw); err == nil {
			var p struct {
				Claims []struct {
					Typ string `json:"typ"`
					Val string `json:"val"`
				} `json:"claims"`
			}
			if json.Unmarshal(b, &p) == nil {
				for _, c := range p.Claims {
					switch c.Typ {
					case "groups":
						u.Groups = append(u.Groups, c.Val)
					case "oid", "http://schemas.microsoft.com/identity/claims/objectidentifier":
						u.OID = c.Val
					}
				}
			}
		}
	}
	return u
}

// IsDeployer reports whether the user may change things. Viewers are read-only.
func (a *Authenticator) IsDeployer(u *User) bool {
	if len(a.cfg.DeployerUsers) == 0 && a.cfg.DeployerGroup == "" {
		return true
	}
	for _, d := range a.cfg.DeployerUsers {
		if strings.EqualFold(strings.TrimSpace(d), u.UPN) {
			return true
		}
	}
	if a.cfg.DeployerGroup != "" {
		for _, g := range u.Groups {
			if g == a.cfg.DeployerGroup {
				return true
			}
		}
	}
	return false
}

// readOnlyPost lists POST endpoints that only read or capture, which a viewer
// may use. Every other state-changing request needs the deployer role.
func readOnlyPost(path string) bool {
	for _, suffix := range []string{"/probe", "/snapshot", "/compare", "/score", "/impact", "/impact/observed", "/impact/access", "/rollouts/preview", "/buildplan/preview"} {
		if strings.HasPrefix(path, "/api/tenants/") && strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

func (a *Authenticator) serve(next http.Handler, w http.ResponseWriter, r *http.Request, u *User) {
	u.Role = "viewer"
	if a.IsDeployer(u) {
		u.Role = "deployer"
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
	default:
		if u.Role != "deployer" && !readOnlyPost(r.URL.Path) {
			http.Error(w, `{"error":"your account is read-only on this console (viewer role)"}`, http.StatusForbidden)
			return
		}
	}
	next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), u)))
}

// Routes registers the sign-in endpoints.
func (a *Authenticator) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/login", a.startLogin)
	mux.HandleFunc("GET /auth/callback", a.callback)
	mux.HandleFunc("GET /auth/logout", a.logout)
	mux.HandleFunc("GET /auth/me", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		u := UserFrom(r.Context())
		if u == nil {
			u = &User{}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"user": u, "signInActive": a.Enabled(), "reason": a.Reason()})
	})
}

// ---- flow ----

func (a *Authenticator) startLogin(w http.ResponseWriter, r *http.Request) {
	if !a.Enabled() {
		http.Error(w, "sign-in is not configured: "+a.Reason(), http.StatusPreconditionFailed)
		return
	}
	verifier := randomString(64)
	nonce := randomString(24)
	returnTo := r.URL.Query().Get("returnTo")
	if returnTo == "" || !strings.HasPrefix(returnTo, "/") {
		returnTo = "/"
	}
	// state carries the PKCE verifier, the nonce and where to land afterwards,
	// signed so a tampered round trip is detected rather than followed.
	payload, _ := json.Marshal(map[string]string{"v": verifier, "n": nonce, "r": returnTo})
	signed := a.sign(payload)

	http.SetCookie(w, &http.Cookie{
		Name: stateCookie, Value: signed, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: a.cfg.SecureCookie, MaxAge: 600,
	})

	challenge := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"client_id":             {a.cfg.ClientID},
		"response_type":         {"code"},
		"redirect_uri":          {a.cfg.RedirectURL},
		"response_mode":         {"query"},
		"scope":                 {"openid profile email offline_access"},
		"state":                 {signed},
		"nonce":                 {nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
	}
	http.Redirect(w, r, fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/authorize?%s", a.cfg.TenantID, q.Encode()), http.StatusFound)
}

func (a *Authenticator) callback(w http.ResponseWriter, r *http.Request) {
	if errCode := r.URL.Query().Get("error"); errCode != "" {
		http.Error(w, "sign-in failed: "+errCode+" "+r.URL.Query().Get("error_description"), http.StatusForbidden)
		return
	}
	cookie, err := r.Cookie(stateCookie)
	if err != nil {
		http.Error(w, "sign-in expired, start again", http.StatusBadRequest)
		return
	}
	// A state that does not match the cookie is a cross-site request, not a user.
	if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(r.URL.Query().Get("state"))) != 1 {
		http.Error(w, "sign-in state did not match", http.StatusBadRequest)
		return
	}
	payload, err := a.verify(cookie.Value)
	if err != nil {
		http.Error(w, "sign-in state was tampered with", http.StatusBadRequest)
		return
	}
	var st map[string]string
	if err := json.Unmarshal(payload, &st); err != nil {
		http.Error(w, "unreadable sign-in state", http.StatusBadRequest)
		return
	}

	form := url.Values{
		"client_id":     {a.cfg.ClientID},
		"client_secret": {a.cfg.ClientSecret},
		"code":          {r.URL.Query().Get("code")},
		"redirect_uri":  {a.cfg.RedirectURL},
		"grant_type":    {"authorization_code"},
		"code_verifier": {st["v"]},
		"scope":         {"openid profile email offline_access"},
	}
	resp, err := a.http.Post(
		fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", a.cfg.TenantID),
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		http.Error(w, "could not reach Entra ID: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		http.Error(w, "Entra ID refused the sign-in: "+string(raw), http.StatusForbidden)
		return
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(raw, &tok); err != nil || tok.IDToken == "" {
		http.Error(w, "no identity returned", http.StatusBadGateway)
		return
	}

	claims, err := readClaims(tok.IDToken)
	if err != nil {
		http.Error(w, "unreadable identity: "+err.Error(), http.StatusBadGateway)
		return
	}
	if aud, _ := claims["aud"].(string); aud != a.cfg.ClientID {
		http.Error(w, "identity was issued for a different application", http.StatusForbidden)
		return
	}
	if iss, _ := claims["iss"].(string); !strings.Contains(iss, a.cfg.TenantID) {
		http.Error(w, "identity came from a different tenant", http.StatusForbidden)
		return
	}
	if nonce, _ := claims["nonce"].(string); nonce != st["n"] {
		http.Error(w, "identity did not match this sign-in attempt", http.StatusForbidden)
		return
	}

	u := &User{
		Name:    str(claims["name"]),
		UPN:     firstNonEmpty(str(claims["preferred_username"]), str(claims["upn"]), str(claims["email"])),
		OID:     str(claims["oid"]),
		Groups:  strSlice(claims["groups"]),
		Expires: time.Now().Add(sessionHours * time.Hour).Unix(),
	}
	if err := a.permitted(u); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	body, _ := json.Marshal(u)
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: a.sign(body), Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: a.cfg.SecureCookie, MaxAge: sessionHours * 3600,
	})
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, firstNonEmpty(st["r"], "/"), http.StatusFound)
}

func (a *Authenticator) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, fmt.Sprintf(
		"https://login.microsoftonline.com/%s/oauth2/v2.0/logout?post_logout_redirect_uri=%s",
		a.cfg.TenantID, url.QueryEscape(strings.TrimSuffix(a.cfg.RedirectURL, "/auth/callback")+"/")), http.StatusFound)
}

// permitted applies the optional allow-list and group gate. With neither set,
// anyone in the tenant can sign in, which is why both are surfaced in the UI.
func (a *Authenticator) permitted(u *User) error {
	if len(a.cfg.AllowedUsers) > 0 {
		ok := false
		for _, allowed := range a.cfg.AllowedUsers {
			if strings.EqualFold(strings.TrimSpace(allowed), u.UPN) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("%s is not on this console's allow-list", u.UPN)
		}
	}
	if a.cfg.AllowedGroup != "" {
		for _, g := range u.Groups {
			if g == a.cfg.AllowedGroup {
				return nil
			}
		}
		return fmt.Errorf("%s is not in the group allowed to use this console", u.UPN)
	}
	return nil
}

func (a *Authenticator) session(r *http.Request) (*User, error) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, err
	}
	payload, err := a.verify(c.Value)
	if err != nil {
		return nil, err
	}
	var u User
	if err := json.Unmarshal(payload, &u); err != nil {
		return nil, err
	}
	if time.Now().Unix() > u.Expires {
		return nil, fmt.Errorf("session expired")
	}
	return &u, nil
}

// ---- signing ----

func (a *Authenticator) sign(payload []byte) string {
	mac := hmac.New(sha256.New, a.cfg.SessionKey)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (a *Authenticator) verify(token string) ([]byte, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("malformed token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	want, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, a.cfg.SessionKey)
	mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), want) {
		return nil, fmt.Errorf("signature mismatch")
	}
	return payload, nil
}

// readClaims decodes the ID token body. The token arrived over TLS from the
// token endpoint, so its signature does not need separate verification.
func readClaims(idToken string) (map[string]any, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a JWT")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, err
	}
	if exp, ok := claims["exp"].(float64); ok && time.Now().Unix() > int64(exp) {
		return nil, fmt.Errorf("identity already expired")
	}
	return claims, nil
}

func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// NewSessionKey generates a key for signing session cookies. Without a
// configured key sessions would survive a restart only by accident.
func NewSessionKey() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}

func str(v any) string { s, _ := v.(string); return s }

func strSlice(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, i := range items {
		if s, ok := i.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
