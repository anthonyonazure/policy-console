// Package equiv decides whether a live Conditional Access policy already does
// what a template does, whatever either of them is called.
//
// Matching by name made a tenant that blocks legacy authentication under its
// own policy name look completely unprotected. It also let a template called
// "phishing-resistant" grant ordinary MFA for years without anyone noticing.
// Both failures come from trusting the label, so this package reads behavior.
//
// A live policy covers a template when it applies the same or a stronger
// control, to the same or a wider set of people, apps and client types, under
// conditions that are no narrower. Exclusions are ignored for coverage, since
// break-glass exclusions are expected, but they are reported.
package equiv

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Built-in authentication strengths, ordered weakest to strongest. Ordinary MFA
// accepts SMS and voice; phishing-resistant accepts only Windows Hello, FIDO2
// and certificates.
const (
	StrengthMFA               = "00000000-0000-0000-0000-000000000002"
	StrengthPasswordless      = "00000000-0000-0000-0000-000000000003"
	StrengthPhishingResistant = "00000000-0000-0000-0000-000000000004"
)

// Action is what a policy demands, ranked so a stronger action can satisfy a
// weaker one. Block sits apart: it is a different outcome, not a stronger MFA.
type Action struct {
	Block          bool
	MFALevel       int // 0 none, 1 MFA, 2 passwordless, 3 phishing-resistant
	PasswordChange bool
	Session        bool // any session control such as sign-in frequency
	CustomStrength bool // a tenant-defined strength we cannot rank
	// Grant holds every grant requirement other than block, MFA and password
	// change: compliantdevice, domainjoineddevice, approvedapplication,
	// compliantapplication, verifiedid. Risk remediation is folded into
	// PasswordChange, which is the older control for the same remedy.
	Grant map[string]bool
	// All is true when the grant operator is AND: every requirement must be
	// met. Otherwise any one requirement is enough.
	All      bool
	Sessions map[string]bool // which session controls are set
}

// requirement is one way of passing a grant: the controls a sign-in presents.
type requirement struct {
	mfa   int
	other map[string]bool
}

// paths lists every way a sign-in can satisfy this action's grant. With OR each
// requirement is its own path; with AND there is one path holding all of them.
func (a Action) paths() []requirement {
	var reqs []requirement
	add := func(r requirement) { reqs = append(reqs, r) }
	if a.All {
		r := requirement{mfa: a.MFALevel, other: map[string]bool{}}
		for k := range a.Grant {
			r.other[k] = true
		}
		if a.PasswordChange {
			r.other["passwordchange"] = true
		}
		return []requirement{r}
	}
	if a.MFALevel > 0 {
		add(requirement{mfa: a.MFALevel, other: map[string]bool{}})
	}
	for k := range a.Grant {
		add(requirement{other: map[string]bool{k: true}})
	}
	if a.PasswordChange {
		add(requirement{other: map[string]bool{"passwordchange": true}})
	}
	return reqs
}

func (a Action) hasGrant() bool { return a.MFALevel > 0 || len(a.Grant) > 0 || a.PasswordChange }

// satisfies reports whether presenting r passes grant a.
func (a Action) satisfies(r requirement) bool {
	if a.All {
		if r.mfa < a.MFALevel {
			return false
		}
		for k := range a.Grant {
			if !r.other[k] {
				return false
			}
		}
		return !a.PasswordChange || r.other["passwordchange"]
	}
	if a.MFALevel > 0 && r.mfa >= a.MFALevel {
		return true
	}
	for k := range a.Grant {
		if r.other[k] {
			return true
		}
	}
	return a.PasswordChange && r.other["passwordchange"]
}

func (a Action) String() string {
	switch {
	case a.Block:
		return "block"
	case a.MFALevel == 3:
		return "phishing-resistant MFA"
	case a.MFALevel == 2:
		return "passwordless MFA"
	case a.MFALevel == 1 && a.PasswordChange:
		return "MFA and password change"
	case a.MFALevel == 1:
		return "MFA"
	case len(a.Grant) > 0 && a.MFALevel == 0:
		keys := make([]string, 0, len(a.Grant))
		for k := range a.Grant {
			keys = append(keys, grantWords[k])
		}
		sort.Strings(keys)
		joiner := " or "
		if a.All {
			joiner = " and "
		}
		return strings.Join(keys, joiner)
	case a.CustomStrength:
		return "custom authentication strength"
	case a.Session:
		return "session limits"
	}
	return "no grant control"
}

var grantWords = map[string]string{
	"compliantdevice":      "compliant device",
	"domainjoineddevice":   "hybrid-joined device",
	"approvedapplication":  "approved app",
	"compliantapplication": "app protection policy",
	"verifiedid":           "verified ID",
}

// Shape is the behavior of one Conditional Access policy.
type Shape struct {
	Name              string
	State             string
	Action            Action
	AllUsers          bool
	Roles             map[string]bool
	Guests            bool
	Groups            []string // specific groups or users; we cannot compare membership
	AllApps           bool
	Apps              map[string]bool
	UserActions       map[string]bool
	ClientTypes       map[string]bool // empty or "all" means all
	DeviceCode        bool
	SignInRisk        map[string]bool
	UserRisk          map[string]bool
	LocationShape     string // "", "specific-list", "outside-trusted"
	Platforms         bool
	ExcludedPlatforms []string // platforms carved out, e.g. android and ios on an MFA policy
	DeviceFilter      bool
	Excluded          int // excluded users and groups, for reporting only
	// Special lists conditions this package does not model in detail, such as
	// agent identities or insider risk. Two policies only resemble each other
	// when these match, and a policy carrying them is narrower than it looks.
	Special []string
	NoUsers bool // includeUsers is "None": the policy targets something other than people
}

func set(v any) map[string]bool {
	out := map[string]bool{}
	if items, ok := v.([]any); ok {
		for _, i := range items {
			if s, ok := i.(string); ok && s != "" {
				out[strings.ToLower(s)] = true
			}
		}
	}
	return out
}

func obj(m map[string]any, k string) map[string]any {
	v, _ := m[k].(map[string]any)
	if v == nil {
		return map[string]any{}
	}
	return v
}

// Parse reads a Conditional Access policy document.
func Parse(body []byte) (*Shape, error) {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	s := &Shape{}
	s.Name, _ = doc["displayName"].(string)
	s.State, _ = doc["state"].(string)

	cond := obj(doc, "conditions")
	users := obj(cond, "users")
	inc := set(users["includeUsers"])
	s.AllUsers = inc["all"]
	s.Roles = set(users["includeRoles"])
	if g, ok := users["includeGuestsOrExternalUsers"].(map[string]any); ok && len(g) > 0 {
		s.Guests = true
	}
	if inc["guestsorexternalusers"] {
		s.Guests = true
	}
	for u := range inc {
		if u != "all" && u != "guestsorexternalusers" && u != "none" {
			s.Groups = append(s.Groups, u)
		}
	}
	for g := range set(users["includeGroups"]) {
		s.Groups = append(s.Groups, g)
	}
	s.Excluded = len(set(users["excludeUsers"])) + len(set(users["excludeGroups"]))
	s.NoUsers = inc["none"]
	for _, k := range []string{"insiderRiskLevels", "agentIdRiskLevels", "agentSessionRiskLevels", "servicePrincipalRiskLevels", "clientApplications", "agents", "agentContext", "authenticationFlows"} {
		switch v := cond[k].(type) {
		case []any:
			if len(v) > 0 {
				s.Special = append(s.Special, k)
			}
		case string:
			if v != "" {
				s.Special = append(s.Special, k)
			}
		case map[string]any:
			if hasContent(v) {
				s.Special = append(s.Special, k)
			}
		}
	}
	sort.Strings(s.Special)

	apps := obj(cond, "applications")
	appSet := set(apps["includeApplications"])
	s.AllApps = appSet["all"]
	s.Apps = appSet
	s.UserActions = set(apps["includeUserActions"])

	s.ClientTypes = set(cond["clientAppTypes"])
	if flows := obj(cond, "authenticationFlows"); strings.Contains(strings.ToLower(fmt.Sprint(flows["transferMethods"])), "devicecodeflow") {
		s.DeviceCode = true
	}
	s.SignInRisk = set(cond["signInRiskLevels"])
	s.UserRisk = set(cond["userRiskLevels"])

	loc := obj(cond, "locations")
	incLoc, excLoc := set(loc["includeLocations"]), set(loc["excludeLocations"])
	switch {
	case incLoc["all"] && len(excLoc) > 0:
		s.LocationShape = "outside-trusted"
	case len(incLoc) > 0 && !incLoc["all"]:
		s.LocationShape = "specific-list"
	}
	plat := obj(cond, "platforms")
	incPlat, excPlat := set(plat["includePlatforms"]), set(plat["excludePlatforms"])
	if (len(incPlat) > 0 && !incPlat["all"]) || len(excPlat) > 0 {
		s.Platforms = true
	}
	for p := range excPlat {
		s.ExcludedPlatforms = append(s.ExcludedPlatforms, p)
	}
	sort.Strings(s.ExcludedPlatforms)
	if d := obj(cond, "devices"); len(d) > 0 {
		if f := obj(d, "deviceFilter"); f["rule"] != nil {
			s.DeviceFilter = true
		}
	}

	grant := obj(doc, "grantControls")
	built := set(grant["builtInControls"])
	s.Action.Block = built["block"]
	s.Action.PasswordChange = built["passwordchange"] || built["riskremediation"]
	s.Action.All = strings.EqualFold(str(grant["operator"]), "AND")
	s.Action.Grant = map[string]bool{}
	for k := range built {
		switch k {
		case "block", "mfa", "passwordchange", "riskremediation":
		default:
			s.Action.Grant[k] = true
		}
	}
	if built["mfa"] {
		s.Action.MFALevel = 1
	}
	if st := obj(grant, "authenticationStrength"); st["id"] != nil {
		switch strings.ToLower(fmt.Sprint(st["id"])) {
		case StrengthMFA:
			s.Action.MFALevel = max(s.Action.MFALevel, 1)
		case StrengthPasswordless:
			s.Action.MFALevel = max(s.Action.MFALevel, 2)
		case StrengthPhishingResistant:
			s.Action.MFALevel = max(s.Action.MFALevel, 3)
		default:
			s.Action.CustomStrength = true
		}
	}
	s.Action.Sessions = map[string]bool{}
	for k, v := range obj(doc, "sessionControls") {
		if strings.HasPrefix(k, "@odata") || v == nil {
			continue
		}
		if m, ok := v.(map[string]any); ok && !hasContent(m) {
			continue
		}
		if b, ok := v.(bool); ok && !b {
			continue
		}
		s.Action.Sessions[strings.ToLower(k)] = true
		s.Action.Session = true
	}
	return s, nil
}

func hasContent(m map[string]any) bool {
	for k, v := range m {
		if strings.HasPrefix(k, "@odata") || v == nil {
			continue
		}
		switch x := v.(type) {
		case []any:
			if len(x) > 0 {
				return true
			}
		case string:
			if x != "" {
				return true
			}
		case map[string]any:
			if hasContent(x) {
				return true
			}
		default:
			return true
		}
	}
	return false
}

// BlocksEveryone reports a policy that would block every user from every app
// with nothing narrowing it: the configuration that locks a tenant out,
// administrators and break-glass accounts included unless they are excluded.
func BlocksEveryone(s *Shape) bool {
	return s.Action.Block && s.AllUsers && s.AllApps && len(s.UserActions) == 0 &&
		allClients(s.ClientTypes) && !s.DeviceCode && len(s.SignInRisk) == 0 && len(s.UserRisk) == 0 &&
		s.LocationShape == "" && !s.Platforms && !s.DeviceFilter && len(s.Special) == 0
}

// Verdict explains whether and how a live policy covers a template.
type Verdict struct {
	Covers  bool     `json:"covers"`
	Exact   bool     `json:"exact"`   // same behavior, not merely broader
	Reasons []string `json:"reasons"` // why it does not cover, or caveats if it does
}

// Covers reports whether live does at least what tmpl does.
func Covers(live, tmpl *Shape) Verdict {
	v := Verdict{Covers: true, Exact: true}
	no := func(format string, args ...any) {
		v.Covers = false
		v.Reasons = append(v.Reasons, fmt.Sprintf(format, args...))
	}
	broader := func() { v.Exact = false }

	// What it demands.
	switch {
	case tmpl.Action.Block != live.Action.Block:
		no("template %s, live policy %s", tmpl.Action, live.Action)
	case !tmpl.Action.Block:
		if tmpl.Action.CustomStrength || live.Action.CustomStrength {
			if tmpl.Action.CustomStrength != live.Action.CustomStrength || tmpl.Action.MFALevel > live.Action.MFALevel {
				no("uses a custom authentication strength that cannot be compared")
			}
		}
		// A live policy covers the template's grant only if every way of
		// passing the live policy also passes the template. "MFA or a
		// compliant device" does not cover "MFA": a compliant device with no
		// MFA gets through.
		if tmpl.Action.hasGrant() {
			paths := live.Action.paths()
			if len(paths) == 0 {
				no("template requires %s, live policy grants no controls", tmpl.Action)
			}
			for _, pth := range paths {
				if !tmpl.Action.satisfies(pth) {
					switch {
					case pth.mfa > 0 && pth.mfa < tmpl.Action.MFALevel && len(tmpl.Action.Grant) == 0:
						no("template requires %s, live policy only %s", tmpl.Action, live.Action)
					case tmpl.Action.PasswordChange && !pth.other["passwordchange"] && tmpl.Action.MFALevel <= pth.mfa && len(tmpl.Action.Grant) == 0:
						no("template also forces a password change")
					default:
						no("template requires %s, but the live policy also lets sign-ins through with %s", tmpl.Action, describePath(pth))
					}
					break
				}
			}
			if live.Action.MFALevel > tmpl.Action.MFALevel && tmpl.Action.MFALevel > 0 {
				broader()
			}
		}
		// Session controls are compared by kind: sign-in frequency does not
		// stand in for app-enforced restrictions.
		missingSession := []string{}
		for k := range tmpl.Action.Sessions {
			if !live.Action.Sessions[k] {
				missingSession = append(missingSession, k)
			}
		}
		sort.Strings(missingSession)
		if !tmpl.Action.hasGrant() && len(missingSession) > 0 {
			no("template sets %s, live policy does not", strings.Join(missingSession, ", "))
		} else if len(missingSession) > 0 {
			// The control is met, but the template's forced re-authentication (for
			// example "every time" on a risky sign-in) is not.
			v.Exact = false
			v.Reasons = append(v.Reasons, "live policy does not apply the template's sign-in frequency or session limits")
		}
	}

	// Who it applies to.
	switch {
	case live.AllUsers:
		if !tmpl.AllUsers {
			broader()
		}
	case tmpl.AllUsers:
		no("template applies to all users, live policy to a subset")
	case len(tmpl.Groups) > 0:
		// Placeholder groups (break-glass) cannot be compared against a client's
		// real group ids, so only an all-users policy can be said to cover them.
		no("template targets specific groups, which cannot be matched to this tenant's groups")
	case tmpl.Guests && !live.Guests:
		no("template applies to guests, live policy does not")
	case len(tmpl.Roles) > 0:
		missing := 0
		for r := range tmpl.Roles {
			if !live.Roles[r] {
				missing++
			}
		}
		if missing > 0 {
			no("live policy covers %d of the template's %d admin roles", len(tmpl.Roles)-missing, len(tmpl.Roles))
		} else if len(live.Roles) > len(tmpl.Roles) {
			broader()
		}
	}

	// Which apps and actions.
	if len(tmpl.UserActions) > 0 {
		for a := range tmpl.UserActions {
			if !live.UserActions[a] {
				no("template applies to the %q user action, live policy does not", a)
			}
		}
	} else if !live.AllApps {
		if tmpl.AllApps {
			no("template applies to all apps, live policy to specific apps")
		} else {
			for a := range tmpl.Apps {
				if !live.Apps[a] {
					no("live policy does not include app %s", a)
				}
			}
		}
	} else if !tmpl.AllApps {
		broader()
	}

	// Client types: all covers any subset.
	if !allClients(live.ClientTypes) {
		if allClients(tmpl.ClientTypes) {
			no("template applies to all client types, live policy to %s", keys(live.ClientTypes))
		} else {
			for c := range tmpl.ClientTypes {
				if !live.ClientTypes[c] {
					no("live policy does not include client type %s", c)
				}
			}
		}
	} else if !allClients(tmpl.ClientTypes) {
		broader()
	}

	// Conditions narrow a policy. The live policy may only use a condition the
	// template also uses, and then no more narrowly.
	if live.DeviceCode && !tmpl.DeviceCode {
		no("live policy only applies to device code flow")
	} else if tmpl.DeviceCode && !live.DeviceCode {
		// A block on everything covers a block on device code flow.
		if !(live.Action.Block && tmpl.Action.Block) {
			no("template applies to device code flow")
		} else {
			broader()
		}
	}
	if len(live.SignInRisk) > 0 && !subset(tmpl.SignInRisk, live.SignInRisk) {
		no("live policy only applies at sign-in risk %s, template at %s", keys(live.SignInRisk), orAny(tmpl.SignInRisk))
	} else if len(tmpl.SignInRisk) > 0 && len(live.SignInRisk) == 0 {
		broader()
	}
	if len(live.UserRisk) > 0 && !subset(tmpl.UserRisk, live.UserRisk) {
		no("live policy only applies at user risk %s, template at %s", keys(live.UserRisk), orAny(tmpl.UserRisk))
	} else if len(tmpl.UserRisk) > 0 && len(live.UserRisk) == 0 {
		broader()
	}
	switch {
	case live.LocationShape == "":
		if tmpl.LocationShape != "" {
			broader()
		}
	case live.LocationShape == tmpl.LocationShape:
		v.Reasons = append(v.Reasons, "location lists compared by shape only; the countries themselves were not checked")
	case live.LocationShape == "outside-trusted" && tmpl.LocationShape == "specific-list" && tmpl.Action.Block:
		// Blocking everything outside a trusted list also blocks a named list of
		// high-risk countries, provided those are not in the trusted list.
		broader()
		v.Reasons = append(v.Reasons, "blocks everything outside its trusted locations, which covers a high-risk country list unless one of those countries is trusted")
	default:
		no("live policy only applies to %s locations", live.LocationShape)
	}
	for _, sp := range live.Special {
		found := false
		for _, t := range tmpl.Special {
			if t == sp {
				found = true
			}
		}
		if !found {
			no("live policy only applies under a %s condition", sp)
		}
	}
	for _, sp := range tmpl.Special {
		found := false
		for _, l := range live.Special {
			if l == sp {
				found = true
			}
		}
		if !found && !(live.AllUsers && live.AllApps && live.Action.Block == tmpl.Action.Block && len(live.Special) == 0 && !tmpl.NoUsers) {
			no("template applies under a %s condition the live policy does not have", sp)
		}
	}
	if tmpl.NoUsers && !live.NoUsers {
		no("template targets non-human identities, not users")
	}
	if live.Platforms && !tmpl.Platforms {
		no("live policy only applies to some device platforms")
	}
	if live.DeviceFilter && !tmpl.DeviceFilter {
		no("live policy only applies to devices matching a filter")
	} else if tmpl.DeviceFilter && !live.DeviceFilter {
		if !(live.Action.Block && tmpl.Action.Block) {
			no("template targets devices by filter, live policy does not")
		} else {
			// Blocking everyone is broader than blocking unmanaged devices, but a
			// live policy that blocks everyone for all apps would lock the tenant
			// out, so this is almost certainly not a real match.
			no("template blocks only unmanaged devices; a live block without a device filter is a different policy")
		}
	}

	if v.Covers && live.Excluded > 0 {
		v.Reasons = append(v.Reasons, fmt.Sprintf("live policy excludes %d users or groups", live.Excluded))
	}
	if !v.Covers {
		v.Exact = false
	}
	return v
}

func allClients(m map[string]bool) bool { return len(m) == 0 || m["all"] }

func subset(small, big map[string]bool) bool {
	if len(small) == 0 {
		return false
	}
	for k := range small {
		if !big[k] {
			return false
		}
	}
	return true
}

func keys(m map[string]bool) string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

func orAny(m map[string]bool) string {
	if len(m) == 0 {
		return "any level"
	}
	return keys(m)
}

func describePath(r requirement) string {
	var parts []string
	switch {
	case r.mfa == 3:
		parts = append(parts, "phishing-resistant MFA")
	case r.mfa == 2:
		parts = append(parts, "passwordless MFA")
	case r.mfa == 1:
		parts = append(parts, "MFA")
	}
	keys := make([]string, 0, len(r.other))
	for k := range r.other {
		w := grantWords[k]
		if w == "" {
			w = k
		}
		keys = append(keys, w)
	}
	sort.Strings(keys)
	parts = append(parts, keys...)
	if len(parts) == 0 {
		return "nothing"
	}
	return strings.Join(parts, " and ")
}

// Describe is a one-line plain account of what a policy does.
func Describe(s *Shape) string {
	who := "specific users or groups"
	switch {
	case s.AllUsers:
		who = "all users"
	case len(s.Roles) > 0:
		who = fmt.Sprintf("%d admin roles", len(s.Roles))
	case s.Guests:
		who = "guests"
	}
	what := "all apps"
	switch {
	case len(s.UserActions) > 0:
		what = "security info registration"
	case !s.AllApps:
		what = fmt.Sprintf("%d apps", len(s.Apps))
	}
	extra := []string{}
	if !allClients(s.ClientTypes) {
		extra = append(extra, "clients "+keys(s.ClientTypes))
	}
	if s.DeviceCode {
		extra = append(extra, "device code flow")
	}
	if len(s.SignInRisk) > 0 {
		extra = append(extra, "sign-in risk "+keys(s.SignInRisk))
	}
	if len(s.UserRisk) > 0 {
		extra = append(extra, "user risk "+keys(s.UserRisk))
	}
	if s.LocationShape != "" {
		extra = append(extra, s.LocationShape+" locations")
	}
	if s.DeviceFilter {
		extra = append(extra, "device filter")
	}
	if len(s.ExcludedPlatforms) > 0 {
		extra = append(extra, "except "+strings.Join(s.ExcludedPlatforms, ", "))
	} else if s.Platforms {
		extra = append(extra, "some device platforms")
	}
	out := fmt.Sprintf("%s for %s on %s", s.Action, who, what)
	if len(extra) > 0 {
		out += " (" + strings.Join(extra, "; ") + ")"
	}
	return out
}

// AuditName checks a policy's name against what it actually does. A policy
// called "phishing-resistant" that accepts SMS is worse than one honestly
// called "MFA", because everyone reading the name believes it is stronger.
func AuditName(s *Shape) []string {
	var out []string
	name := strings.ToLower(s.Name)
	if strings.Contains(name, "phishing-resistant") || strings.Contains(name, "phishing resistant") {
		if s.Action.MFALevel < 3 && !s.Action.CustomStrength {
			out = append(out, fmt.Sprintf("named phishing-resistant but grants %s, which accepts SMS and voice calls", s.Action))
		}
	}
	if strings.Contains(name, "passwordless") && s.Action.MFALevel < 2 && !s.Action.CustomStrength {
		out = append(out, fmt.Sprintf("named passwordless but grants %s", s.Action))
	}
	if strings.Contains(name, "untrusted location") && s.LocationShape != "outside-trusted" {
		out = append(out, "named as applying to untrusted locations but has no trusted-location exclusion, so it applies at every location")
	}
	if !s.Action.Block && s.Action.MFALevel > 0 && len(s.ExcludedPlatforms) > 0 {
		out = append(out, fmt.Sprintf("does not require MFA on %s: those platforms are excluded", strings.Join(s.ExcludedPlatforms, " or ")))
	}
	if strings.Contains(name, "block") && !s.Action.Block {
		out = append(out, fmt.Sprintf("named as a block but grants %s", s.Action))
	}
	if strings.Contains(name, "mfa") && !s.Action.Block && s.Action.MFALevel == 0 && !s.Action.CustomStrength {
		out = append(out, "named as requiring MFA but has no MFA grant control")
	}
	return out
}

func str(v any) string { x, _ := v.(string); return x }
