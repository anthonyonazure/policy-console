// Package wizard turns a handful of answers about a client into an ordered build
// plan for their Intune environment: what to check first, what to set up by
// hand, which policy packs to deploy, and what must be proven before the next
// step. It only plans. Running a step goes through the console's normal preview,
// confirmation and safety checks.
package wizard

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/impact"
)

// Answers are what the technician tells the wizard about the client.
type Answers struct {
	Platforms     []string `json:"platforms"`     // Windows, macOS, iOS, Android
	Ownership     string   `json:"ownership"`     // corporate | byod | both
	ThirdPartyEDR bool     `json:"thirdPartyEDR"` // Defender policies are not wanted
	RMMPatching   bool     `json:"rmmPatching"`
	Regulated     bool     `json:"regulated"`  // HIPAA, CMMC or similar
	Brownfield    bool     `json:"brownfield"` // the tenant already has policies
}

const (
	TypeDeploy = "deploy" // the console creates policies
	TypeManual = "manual" // a person does it in a portal; the console cannot yet
	TypeCheck  = "check"  // the console reads the tenant and reports
	TypeGate   = "gate"   // a person confirms something is true before going on
)

// Step is one thing to do.
type Step struct {
	ID          string   `json:"id"`
	Pack        string   `json:"pack"`
	Title       string   `json:"title"`
	Why         string   `json:"why"`
	Type        string   `json:"type"`
	TemplateIDs []string `json:"templateIds,omitempty"`
	DependsOn   []string `json:"dependsOn,omitempty"`
	Notes       []string `json:"notes,omitempty"`
}

// Plan is the ordered result.
type Plan struct {
	Steps  []Step   `json:"steps"`
	Counts Counts   `json:"counts"`
	Notes  []string `json:"notes,omitempty"`
}

type Counts struct {
	Steps     int `json:"steps"`
	Deploy    int `json:"deploy"`
	Manual    int `json:"manual"`
	Templates int `json:"templates"`
}

var validPlatforms = map[string]bool{"Windows": true, "macOS": true, "iOS": true, "Android": true}

// Normalize cleans answers and fills sensible defaults.
func (a Answers) Normalize() Answers {
	seen := map[string]bool{}
	var ps []string
	for _, p := range a.Platforms {
		p = strings.TrimSpace(p)
		if validPlatforms[p] && !seen[p] {
			seen[p] = true
			ps = append(ps, p)
		}
	}
	if len(ps) == 0 {
		ps = []string{"Windows"}
	}
	sort.Strings(ps)
	a.Platforms = ps
	switch a.Ownership {
	case "corporate", "byod", "both":
	default:
		a.Ownership = "corporate"
	}
	return a
}

// Build makes the plan from answers and the templates the console holds.
func Build(a Answers, templates []catalog.Template) Plan {
	a = a.Normalize()
	has := map[string]bool{}
	for _, p := range a.Platforms {
		has[p] = true
	}
	var steps []Step
	add := func(s Step) { steps = append(steps, s) }

	add(Step{ID: "discover", Pack: "Discovery", Type: TypeCheck, Title: "Look at what the client already has",
		Why: "Before changing anything, record the enrollment status, the devices, the operating system spread and the existing policies. This becomes the before picture for the handover report."})
	if a.Brownfield {
		add(Step{ID: "conflicts", Pack: "Discovery", Type: TypeCheck, DependsOn: []string{"discover"}, Title: "Find existing policies that overlap the new ones",
			Why:   "An existing policy with the same name is reused, never updated, and policies that do the same job fight each other. New device policies are deployed unassigned, then groups move across one at a time.",
			Notes: []string{"Compare each existing policy with the template before assuming it matches."}})
	}
	add(Step{ID: "foundations", Pack: "Foundations", Type: TypeManual, DependsOn: []string{"discover"}, Title: "Create the groups and filters the policies target",
		Why:   "Pilot, platform and ownership groups are what rings and assignments point at.",
		Notes: []string{"Not automated yet: create dynamic device groups per platform and a pilot group, plus any assignment filters and scope tags."}})
	add(Step{ID: "mdm-enrollment", Pack: "Enrollment", Type: TypeManual, DependsOn: []string{"discover"}, Title: "Check that devices enroll automatically",
		Why:   "Policies only reach devices that are enrolled. Confirm MDM user scope and Entra join auto enrollment are on for the right people.",
		Notes: []string{"Not automated yet: read the enrollment settings in the portal and note who is covered."}})
	if has["macOS"] || has["iOS"] {
		add(Step{ID: "apple-prereqs", Pack: "Enrollment", Type: TypeManual, DependsOn: []string{"discover"}, Title: "Apple setup: push certificate and Business Manager token",
			Why: "Apple devices cannot be managed without the push certificate, and corporate Apple devices need the Business Manager token. The console cannot create these."})
	}
	if has["Android"] {
		add(Step{ID: "android-prereqs", Pack: "Enrollment", Type: TypeManual, DependsOn: []string{"discover"}, Title: "Android setup: bind Android Enterprise",
			Why: "Android devices cannot be managed until the tenant is bound to Android Enterprise. The console cannot do this."})
	}

	comp := pick(templates, a, func(t catalog.Template) bool { return t.Category == "pack-compliance" })
	if len(comp) > 0 {
		add(Step{ID: "compliance", Pack: "Compliance", Type: TypeDeploy, TemplateIDs: ids(comp), DependsOn: []string{"foundations", "mdm-enrollment"},
			Title: "Create the compliance policies",
			Why:   "Compliance decides which devices count as healthy. They are created unassigned, so nothing changes for anyone until a rollout assigns them.",
			Notes: []string{"Preview who would pass or fail before assigning (the impact preview)."}})
	}

	sec := pick(templates, a, func(t catalog.Template) bool {
		if t.Category == "intune" {
			return true
		}
		return t.Category == "defender" && !a.ThirdPartyEDR
	})
	if len(sec) > 0 {
		notes := []string{"Created unassigned; move device groups onto them one at a time."}
		if a.ThirdPartyEDR {
			notes = append(notes, "Defender policies are left out because another product does endpoint protection.")
		}
		add(Step{ID: "security", Pack: "Security and configuration", Type: TypeDeploy, TemplateIDs: ids(sec), DependsOn: []string{"foundations", "mdm-enrollment"},
			Title: "Create the security and configuration policies",
			Why:   "Endpoint protection, BitLocker, firewall and device settings.", Notes: notes})
	}

	if (has["iOS"] || has["Android"]) && a.Ownership != "corporate" {
		mob := pick(templates, a, func(t catalog.Template) bool { return t.Category == "oib-byod" })
		if len(mob) > 0 {
			add(Step{ID: "mobile", Pack: "Mobile", Type: TypeDeploy, TemplateIDs: ids(mob), DependsOn: []string{"foundations"},
				Title: "Create the phone app protection policies",
				Why:   "Personal phones are protected at the app level: PIN, no copying work data into personal apps."})
		}
	}

	pilotDeps := []string{}
	for _, id := range []string{"compliance", "security", "mobile"} {
		for _, s := range steps {
			if s.ID == id {
				pilotDeps = append(pilotDeps, id)
			}
		}
	}
	if len(pilotDeps) > 0 {
		add(Step{ID: "pilot", Pack: "Pilot", Type: TypeGate, DependsOn: pilotDeps, Title: "Prove it on a pilot group",
			Why:   "Assign the policies to a small pilot group and confirm every enrolled pilot device reports compliant before anyone else is affected.",
			Notes: []string{"Enroll the pilot devices before turning on any Conditional Access policy that needs a compliant or managed device."}})
	}

	ca := pick(templates, a, func(t catalog.Template) bool {
		return t.Category == "conditional-access" && t.Kind == catalog.KindConditionalAccess
	})
	var core, device []catalog.Template
	for _, t := range ca {
		if t.Code == "C015" || t.Code == "C017" {
			device = append(device, t)
		} else {
			core = append(core, t)
		}
	}
	if len(core) > 0 {
		deps := []string{"foundations"}
		add(Step{ID: "identity", Pack: "Identity", Type: TypeDeploy, TemplateIDs: ids(core), DependsOn: deps,
			Title: "Create the sign-in protection (Conditional Access) in report-only",
			Why:   "Report-only shows who would be affected without blocking anyone. Leave it for at least 48 hours before enforcing.",
			Notes: []string{"Keep the break-glass accounts excluded."}})
	}
	if a.Brownfield == false && len(core) > 0 {
		add(Step{ID: "security-defaults", Pack: "Identity", Type: TypeManual, DependsOn: []string{"identity"}, Title: "Switch Security Defaults off and the new policies on, together",
			Why: "Security Defaults and Conditional Access do not run together. Doing both in one change window leaves no gap without multi-factor sign-in."})
	}
	if len(device) > 0 {
		deps := []string{"identity"}
		if len(pilotDeps) > 0 {
			deps = append(deps, "pilot")
		}
		add(Step{ID: "identity-devices", Pack: "Identity", Type: TypeDeploy, TemplateIDs: ids(device), DependsOn: deps,
			Title: "Create the policies that need a managed device",
			Why:   "These lock out unmanaged devices, so they come last and only after the pilot proves devices are compliant."})
	}

	if a.Regulated {
		add(Step{ID: "assess", Pack: "Handover", Type: TypeCheck, DependsOn: lastIDs(steps), Title: "Assess against CIS and CISA SCuBA",
			Why: "A regulated client needs evidence. Run the baseline assessment and keep the report."})
	}
	add(Step{ID: "handover", Pack: "Handover", Type: TypeCheck, DependsOn: lastIDs(steps), Title: "Check the result and write the handover report",
		Why: "Re-read the tenant, compare with the before picture, and give the client a plain English summary."})

	p := Plan{Steps: steps}
	for _, s := range steps {
		p.Counts.Steps++
		p.Counts.Templates += len(s.TemplateIDs)
		switch s.Type {
		case TypeDeploy:
			p.Counts.Deploy++
		case TypeManual, TypeGate:
			p.Counts.Manual++
		}
	}
	if a.RMMPatching {
		p.Notes = append(p.Notes, "A management tool patches devices, so no Windows Update rings are planned.")
	}
	return p
}

func lastIDs(steps []Step) []string {
	if len(steps) == 0 {
		return nil
	}
	return []string{steps[len(steps)-1].ID}
}

func ids(ts []catalog.Template) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.ID)
	}
	return out
}

// pick keeps the templates that match the filter and apply to the chosen platforms.
func pick(all []catalog.Template, a Answers, keep func(catalog.Template) bool) []catalog.Template {
	var out []catalog.Template
	for _, t := range all {
		if !keep(t) || !appliesTo(t, a.Platforms) {
			continue
		}
		out = append(out, t)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// appliesTo is true when a template is for one of the platforms, or for none in
// particular (Conditional Access covers every platform).
func appliesTo(t catalog.Template, platforms []string) bool {
	ts := PlatformsOf(t)
	if len(ts) == 0 {
		return true
	}
	for _, p := range platforms {
		for _, tp := range ts {
			if p == tp {
				return true
			}
		}
	}
	return false
}

// PlatformsOf names the platforms a template is for, from its body.
func PlatformsOf(t catalog.Template) []string {
	var doc map[string]any
	if json.Unmarshal(t.Body, &doc) != nil {
		return nil
	}
	if ot, _ := doc["@odata.type"].(string); ot != "" {
		if p := impact.PlatformOf(ot); p != "" {
			return []string{p}
		}
		low := strings.ToLower(ot)
		switch {
		case strings.Contains(low, "ios"):
			return []string{"iOS"}
		case strings.Contains(low, "android"):
			return []string{"Android"}
		}
	}
	pl, _ := doc["platforms"].(string)
	var out []string
	low := strings.ToLower(pl)
	if strings.Contains(low, "windows") {
		out = append(out, "Windows")
	}
	if strings.Contains(low, "macos") {
		out = append(out, "macOS")
	}
	if strings.Contains(low, "ios") {
		out = append(out, "iOS")
	}
	if strings.Contains(low, "android") {
		out = append(out, "Android")
	}
	return out
}
