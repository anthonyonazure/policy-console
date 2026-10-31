// Package mstemplates brings in Microsoft's own Conditional Access templates:
// the policies Microsoft recommends, published through Graph and updated as the
// product changes. They are the best source to build from, so the console
// compares the House templates and each tenant against them by behavior, and
// can offer any of them for deployment.
package mstemplates

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/equiv"
)

type Grapher interface {
	List(ctx context.Context, uri string) ([]map[string]any, error)
}

type Template struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Scenarios   []string `json:"scenarios"`
	Requires    string   `json:"requires,omitempty"` // licence or feature a small tenant may lack
	// NotDeployable explains why the console will not create this policy
	// itself, for example conditions that only exist in the beta API.
	NotDeployable string          `json:"notDeployable,omitempty"`
	Body          json.RawMessage `json:"body"` // deployable policy, report-only, break-glass excluded
}

// NamePrefix marks policies adopted from Microsoft so they are recognizable in
// a tenant and never collide with the security firm's naming.
const NamePrefix = "Microsoft | "

// Fetch reads Microsoft's templates and turns each into a deployable policy.
func Fetch(ctx context.Context, g Grapher) ([]Template, error) {
	// Beta, not v1.0: v1.0 omits the agent-identity conditions, which turns
	// "block all agent identities" into something that reads as "block
	// everyone". Reading the full definition is a safety requirement.
	items, err := g.List(ctx, "/beta/identity/conditionalAccess/templates")
	if err != nil {
		return nil, err
	}
	var out []Template
	for _, it := range items {
		t := Template{ID: str(it["id"]), Name: str(it["name"]), Description: str(it["description"])}
		if sc, ok := it["scenarios"].(string); ok {
			for _, s := range strings.Split(sc, ",") {
				if s = strings.TrimSpace(s); s != "" {
					t.Scenarios = append(t.Scenarios, s)
				}
			}
		}
		details, _ := it["details"].(map[string]any)
		body, err := deployable(t.Name, details)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", t.Name, err)
		}
		t.Body = body
		t.Requires = requirement(t.Name, details)
		if sh, err := equiv.Parse(body); err == nil {
			for _, sp := range sh.Special {
				if betaOnly[sp] {
					t.NotDeployable = "uses " + sp + ", which the console's v1.0 create call would drop; create it from the Entra portal"
				}
			}
			if equiv.BlocksEveryone(sh) {
				t.NotDeployable = "would block every user from every app"
			}
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// deployable wraps Microsoft's template details into a policy that follows the
// console's rules: report-only, and the emergency access group excluded, since
// a template that locks out the break-glass accounts is how tenants get locked.
func deployable(name string, details map[string]any) ([]byte, error) {
	clean := scrub(details).(map[string]any)
	if cond, ok := clean["conditions"].(map[string]any); ok {
		if users, ok := cond["users"].(map[string]any); ok {
			groups, _ := users["excludeGroups"].([]any)
			users["excludeGroups"] = append(groups, "${EMERGENCY_ACCESS_GROUP_ID}")
		}
	}
	// Graph returns the whole authentication strength object; creating a policy
	// accepts only its id.
	if grant, ok := clean["grantControls"].(map[string]any); ok {
		if st, ok := grant["authenticationStrength"].(map[string]any); ok {
			grant["authenticationStrength"] = map[string]any{"id": st["id"]}
		}
	}
	clean["displayName"] = NamePrefix + name
	clean["state"] = "enabledForReportingButNotEnforced"
	return json.MarshalIndent(clean, "", "  ")
}

// scrub drops nulls, empty lists and Graph annotations, which a create call
// either rejects or ignores.
func scrub(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, val := range x {
			if strings.Contains(k, "@odata") || val == nil {
				continue
			}
			c := scrub(val)
			if l, ok := c.([]any); ok && len(l) == 0 {
				continue
			}
			if m, ok := c.(map[string]any); ok && len(m) == 0 {
				continue
			}
			out[k] = c
		}
		return out
	case []any:
		out := make([]any, 0, len(x))
		for _, i := range x {
			out = append(out, scrub(i))
		}
		return out
	}
	return v
}

// requirement names the licence or feature a template depends on, so a tech
// does not deploy a policy that silently does nothing on a Business Premium
// tenant. These are Microsoft's documented prerequisites for each condition.
func requirement(name string, details map[string]any) string {
	cond, _ := details["conditions"].(map[string]any)
	nonEmpty := func(k string) bool {
		switch v := cond[k].(type) {
		case []any:
			return len(v) > 0
		case string:
			return v != ""
		}
		return false
	}
	switch {
	case nonEmpty("insiderRiskLevels"):
		return "Microsoft Purview Insider Risk Management"
	case strings.Contains(strings.ToLower(name), "agent"):
		return "Microsoft Entra Agent ID"
	case nonEmpty("userRiskLevels") || nonEmpty("signInRiskLevels"):
		return "Microsoft Entra ID P2"
	}
	return ""
}

// Row compares one Microsoft template with a set of existing policies.
type Row struct {
	Template  Template `json:"template"`
	State     string   `json:"state"` // covered | covered-broader | weaker | missing
	By        string   `json:"by,omitempty"`
	LiveState string   `json:"liveState,omitempty"`
	Reasons   []string `json:"reasons,omitempty"`
	Does      string   `json:"does"`
}

// Candidate is a policy that might already do a template's job.
type Candidate struct {
	Name  string
	Body  []byte
	State string
}

// Compare finds, for each Microsoft template, the existing policy that does its
// job. When nothing does, it reports the closest policy and why it falls short,
// which is how a weaker look-alike (ordinary MFA under a phishing-resistant
// name) shows up.
func Compare(ms []Template, cands []Candidate) []Row {
	type shaped struct {
		c Candidate
		s *equiv.Shape
	}
	var shapes []shaped
	for _, c := range cands {
		if s, err := equiv.Parse(c.Body); err == nil {
			shapes = append(shapes, shaped{c, s})
		}
	}
	var rows []Row
	for _, t := range ms {
		ts, err := equiv.Parse(t.Body)
		if err != nil {
			continue
		}
		row := Row{Template: t, State: "missing", Does: equiv.Describe(ts)}
		bestMiss := -1
		var missReasons []string
		for _, sh := range shapes {
			v := equiv.Covers(sh.s, ts)
			if v.Covers {
				st := "covered-broader"
				if v.Exact {
					st = "covered"
				}
				// Prefer an enforced match over a report-only one.
				if row.State == "missing" || (row.LiveState != "enabled" && sh.c.State == "enabled") {
					row.State, row.By, row.LiveState, row.Reasons = st, sh.c.Name, sh.c.State, v.Reasons
				}
				continue
			}
			// A near miss is a policy doing the same kind of thing (both block, or
			// both challenge) about the same kind of target, falling short on one
			// or two points. Anything else is a different policy, not a weaker one.
			if !sameKind(sh.s, ts) {
				continue
			}
			if row.State == "missing" && len(v.Reasons) <= 2 && (bestMiss == -1 || len(v.Reasons) < bestMiss) {
				bestMiss, missReasons = len(v.Reasons), v.Reasons
				row.By = sh.c.Name
			}
		}
		if row.State == "missing" && bestMiss >= 0 {
			row.State, row.Reasons = "weaker", missReasons
		}
		if row.State == "missing" {
			row.By = ""
		}
		rows = append(rows, row)
	}
	return rows
}

// betaOnly conditions exist only in the beta Conditional Access API.
var betaOnly = map[string]bool{
	"agentIdRiskLevels": true, "agentSessionRiskLevels": true,
	"clientApplications": true, "agents": true, "agentContext": true,
}

func sameKind(a, b *equiv.Shape) bool {
	if strings.Join(a.Special, ",") != strings.Join(b.Special, ",") || a.NoUsers != b.NoUsers {
		return false
	}
	if a.Action.Block != b.Action.Block || a.DeviceCode != b.DeviceCode {
		return false
	}
	if (len(a.UserActions) > 0) != (len(b.UserActions) > 0) {
		return false
	}
	// A session-only policy and a grant policy are different instruments.
	sessionOnly := func(s *equiv.Shape) bool {
		return !s.Action.Block && s.Action.MFALevel == 0 && !s.Action.PasswordChange && !s.Action.CustomStrength
	}
	if sessionOnly(a) != sessionOnly(b) {
		return false
	}
	// Risk-based and device-based policies only resemble their own kind.
	if (len(a.SignInRisk)+len(a.UserRisk) > 0) != (len(b.SignInRisk)+len(b.UserRisk) > 0) {
		return false
	}
	if a.DeviceFilter != b.DeviceFilter || a.Platforms != b.Platforms || a.LocationShape != b.LocationShape {
		return false
	}
	// Blocking legacy clients and blocking a platform are different policies
	// even though both block.
	legacy := func(s *equiv.Shape) bool { return len(s.ClientTypes) > 0 && !s.ClientTypes["all"] }
	return legacy(a) == legacy(b)
}

// AsCatalog turns Microsoft's templates into deployable catalog entries.
func AsCatalog(ms []Template) []catalog.Template {
	var out []catalog.Template
	for _, t := range ms {
		if t.NotDeployable != "" {
			continue
		}
		out = append(out, catalog.FromBody("microsoft", catalog.KindConditionalAccess, "microsoft/"+t.ID+".json", t.Body))
	}
	return out
}

func str(v any) string { s, _ := v.(string); return s }
