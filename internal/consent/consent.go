package consent

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	roleGlobalAdmin         = "62e90394-69f5-4237-9190-012177145e10"
	rolePrivilegedRoleAdmin = "e8611ab8-c189-46e8-94e1-60213ab1f814"
)

var guidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// TokenSource hands back a delegated Graph token for one client tenant, signed
// in as the partner's own administrator through GDAP.
type TokenSource interface {
	Token(ctx context.Context, tenantID string) (string, error)
}

// AzCLI takes the token from the operator's own `az login` session. Nothing is
// stored by the console and no extra app registration is left in the client's
// tenant, which a console sign-in flow of its own would do.
type AzCLI struct {
	Run func(ctx context.Context, name string, args ...string) ([]byte, error) // test seam
}

func (a AzCLI) Token(ctx context.Context, tenantID string) (string, error) {
	if !guidRE.MatchString(tenantID) {
		return "", errors.New("tenant id is not a GUID")
	}
	run := a.Run
	if run == nil {
		run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).Output()
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := run(ctx, "az", "account", "get-access-token", "--resource", "https://graph.microsoft.com",
		"--tenant", tenantID, "--query", "accessToken", "-o", "tsv")
	if err != nil {
		return "", fmt.Errorf("no delegated sign-in for this client. In a terminal, sign in as your partner administrator: az login --tenant %s --allow-no-subscriptions, then try again", tenantID)
	}
	tok := strings.TrimSpace(string(out))
	if tok == "" {
		return "", errors.New("the sign-in session returned no token")
	}
	return tok, nil
}

// Claims are the few token fields the preflight reads.
type Claims struct {
	TenantID string
	Roles    []string
}

// ReadClaims decodes a token's payload WITHOUT verifying its signature. That is
// acceptable only because this is a courtesy check that fails early with a
// plain message; Microsoft Graph still enforces the real permissions.
func ReadClaims(token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("not a signed-in administrator token")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, err
	}
	var c struct {
		TID  string   `json:"tid"`
		Wids []string `json:"wids"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return Claims{}, err
	}
	return Claims{TenantID: c.TID, Roles: c.Wids}, nil
}

// Preflight refuses early, in plain words, when the token cannot do the job.
// The tenant check matters most: a token for the wrong client must never be used.
func Preflight(c Claims, tenantID string) error {
	if !strings.EqualFold(c.TenantID, tenantID) {
		return fmt.Errorf("the signed-in session is for a different client (%s), not this one. Sign in to this client and try again", c.TenantID)
	}
	for _, r := range c.Roles {
		if strings.EqualFold(r, roleGlobalAdmin) || strings.EqualFold(r, rolePrivilegedRoleAdmin) {
			return nil
		}
	}
	return errors.New("your access to this client does not include Privileged Role Administrator or Global Administrator. Microsoft allows only those roles to grant Graph application permissions; add one to the GDAP relationship for this client")
}

// Item is one permission in a plan.
type Item struct {
	Kind       string `json:"kind"`
	Permission string `json:"permission"`
	Why        string `json:"why"`
	RoleID     string `json:"-"`
	Granted    bool   `json:"granted"`
}

// Plan is what a grant would do, shown before anything is written.
type Plan struct {
	TenantID   string   `json:"tenantId"`
	Profile    string   `json:"profile"`
	AppID      string   `json:"appId"`
	HasSP      bool     `json:"servicePrincipalExists"`
	Items      []Item   `json:"items"`
	Missing    int      `json:"missing"`
	Unresolved []string `json:"unresolved,omitempty"` // permissions Microsoft Graph has no such role for; never guessed
	Hash       string   `json:"hash"`

	spID, graphID string
}

// BuildPlan reads the client's state and works out exactly what is missing.
func BuildPlan(ctx context.Context, api API, tenantID, profile, appID string) (*Plan, error) {
	manifest := Manifest(profile)
	if manifest == nil {
		return nil, fmt.Errorf("unknown profile %q (read or write)", profile)
	}
	if !guidRE.MatchString(appID) {
		return nil, errors.New("the application id for this profile is not configured")
	}
	graph, err := api.FindServicePrincipal(ctx, GraphAppID)
	if err != nil {
		return nil, fmt.Errorf("read Microsoft Graph in the client tenant: %w", err)
	}
	if graph == nil {
		return nil, errors.New("Microsoft Graph is not present in the client tenant")
	}
	roles := map[string]AppRole{}
	for _, r := range graph.AppRoles {
		if r.IsEnabled && contains(r.AllowedMemberTypes, "Application") {
			roles[r.Value] = r
		}
	}
	p := &Plan{TenantID: tenantID, Profile: profile, AppID: appID, graphID: graph.ID}

	sp, err := api.FindServicePrincipal(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("look for the console's application in the client tenant: %w", err)
	}
	granted := map[string]bool{} // role id
	if sp != nil {
		p.HasSP, p.spID = true, sp.ID
		as, err := api.Assignments(ctx, sp.ID)
		if err != nil {
			return nil, fmt.Errorf("read existing grants: %w", err)
		}
		for _, a := range as {
			if a.ResourceID == graph.ID {
				granted[strings.ToLower(a.AppRoleID)] = true
			}
		}
	}

	for _, g := range manifest {
		role, ok := roles[g.Permission]
		it := Item{Kind: g.Kind, Permission: g.Permission, Why: g.Why}
		if !ok {
			p.Unresolved = append(p.Unresolved, g.Permission)
			p.Items = append(p.Items, it)
			continue
		}
		it.RoleID = role.ID
		it.Granted = granted[strings.ToLower(role.ID)]
		if !it.Granted {
			p.Missing++
		}
		p.Items = append(p.Items, it)
	}
	p.Hash = p.hash()
	return p, nil
}

// hash fingerprints what the plan would do, so a confirmation applies to the plan
// the person actually saw and not to whatever the client looks like a minute later.
func (p *Plan) hash() string {
	var parts []string
	for _, it := range p.Items {
		if !it.Granted && it.RoleID != "" {
			parts = append(parts, it.Permission+"="+it.RoleID)
		}
	}
	sort.Strings(parts)
	h := sha256.Sum256([]byte(strings.Join([]string{p.TenantID, p.Profile, p.AppID, fmt.Sprint(p.HasSP), strings.Join(parts, ",")}, "|")))
	return hex.EncodeToString(h[:])
}

// GrantedSet lists the permissions the plan found already in place.
func (p *Plan) GrantedSet() map[string]bool {
	out := map[string]bool{}
	for _, it := range p.Items {
		if it.Granted {
			out[it.Permission] = true
		}
	}
	return out
}

// Outcome is the result of one permission in an apply.
type Outcome struct {
	Permission string `json:"permission"`
	Result     string `json:"result"` // granted | already | failed
	Detail     string `json:"detail,omitempty"`
}

// Result of applying a plan.
type Result struct {
	Outcomes []Outcome `json:"outcomes"`
	Verified *Plan     `json:"verified"`
}

var ErrPlanChanged = errors.New("the client changed since the preview, so nothing was granted. Preview again and confirm the new plan")

// Apply grants what the confirmed plan lists, then reads the client back and
// fails if anything is still missing. The read-back is not optional: Microsoft's
// own command has reported success while granting nothing.
func Apply(ctx context.Context, api API, confirmed *Plan, sleep func(time.Duration)) (*Result, error) {
	if sleep == nil {
		sleep = time.Sleep
	}
	fresh, err := BuildPlan(ctx, api, confirmed.TenantID, confirmed.Profile, confirmed.AppID)
	if err != nil {
		return nil, err
	}
	if fresh.Hash != confirmed.Hash {
		return nil, ErrPlanChanged
	}
	if len(fresh.Unresolved) > 0 {
		return nil, fmt.Errorf("Microsoft Graph in this client has no application permission named %s; nothing was granted", strings.Join(fresh.Unresolved, ", "))
	}

	spID := fresh.spID
	if !fresh.HasSP {
		sp, err := api.CreateServicePrincipal(ctx, fresh.AppID)
		if err != nil {
			return nil, fmt.Errorf("add the console's application to the client tenant: %w", err)
		}
		spID = sp.ID
	}

	res := &Result{}
	for _, it := range fresh.Items {
		if it.Granted {
			res.Outcomes = append(res.Outcomes, Outcome{Permission: it.Permission, Result: "already"})
			continue
		}
		err := assignWithRetry(ctx, api, spID, fresh.graphID, it.RoleID, sleep)
		var ae *APIError
		switch {
		case err == nil:
			res.Outcomes = append(res.Outcomes, Outcome{Permission: it.Permission, Result: "granted"})
		case errors.As(err, &ae) && ae.Status == http.StatusConflict:
			res.Outcomes = append(res.Outcomes, Outcome{Permission: it.Permission, Result: "already"})
		default:
			res.Outcomes = append(res.Outcomes, Outcome{Permission: it.Permission, Result: "failed", Detail: err.Error()})
		}
	}

	verified, err := BuildPlan(ctx, api, fresh.TenantID, fresh.Profile, fresh.AppID)
	if err != nil {
		return res, fmt.Errorf("granted, but could not read the client back to verify: %w", err)
	}
	res.Verified = verified
	if verified.Missing > 0 {
		var miss []string
		for _, it := range verified.Items {
			if !it.Granted {
				miss = append(miss, it.Permission)
			}
		}
		return res, fmt.Errorf("Microsoft reported success but %d permission(s) are still not granted: %s", verified.Missing, strings.Join(miss, ", "))
	}
	return res, nil
}

// assignWithRetry covers the short delay before a just-created application is
// visible everywhere in the client's directory.
func assignWithRetry(ctx context.Context, api API, spID, resourceID, roleID string, sleep func(time.Duration)) error {
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		if err = api.Assign(ctx, spID, resourceID, roleID); err == nil {
			return nil
		}
		var ae *APIError
		if !errors.As(err, &ae) || (ae.Status != http.StatusNotFound && ae.Status != http.StatusBadRequest) {
			return err
		}
		sleep(time.Duration(attempt+1) * 2 * time.Second)
	}
	return err
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
