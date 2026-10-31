// Package score turns a comparison into numbers a tech can read out to a
// client: how much of the baseline is deployed, how much of it is actually
// enforced, how far it has drifted, and which published controls that covers.
package score

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/anthonyonazure/policy-console/internal/benchmark"
	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/engine"
)

//go:embed controls.json
var controlsJSON []byte

// Control maps one template to one control in a published framework.
type Control struct {
	Framework string `json:"framework"`
	ID        string `json:"id"`
	Title     string `json:"title,omitempty"`
	Coverage  string `json:"coverage,omitempty"` // full | partial; empty means full
	Note      string `json:"note,omitempty"`
	// ExactOnly means the control asks for a dedicated policy, so a broader
	// tenant policy that happens to cover the template's behavior does not meet
	// it. "Enable sign-in risk policies" is not met by "MFA for everyone".
	ExactOnly bool `json:"exactOnly,omitempty"`
}

type mapping struct {
	Frameworks map[string]string    `json:"frameworks"`
	Verified   map[string]bool      `json:"verified"`
	Templates  map[string][]Control `json:"templates"`
}

var loaded mapping

func init() { _ = json.Unmarshal(controlsJSON, &loaded) }

type CategoryScore struct {
	Category string `json:"category"`
	Total    int    `json:"total"`
	Deployed int    `json:"deployed"`
	Enforced int    `json:"enforced"`
	Drifted  int    `json:"drifted"`
	Missing  int    `json:"missing"`
	Coverage int    `json:"coverage"`
}

type ControlState struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Criticality string `json:"criticality,omitempty"`
	State       string `json:"state"` // met | partial | mapped-not-enforced | no-template
	Via         string `json:"via,omitempty"`
	Note        string `json:"note,omitempty"`
}

type FrameworkScore struct {
	Framework string         `json:"framework"`
	Label     string         `json:"label"`
	Version   string         `json:"version,omitempty"`
	Source    string         `json:"source,omitempty"`
	Total     int            `json:"total"`
	Met       int            `json:"met"`
	Partial   int            `json:"partial"`
	Percent   int            `json:"percent"`
	Verified  bool           `json:"verified"`
	Controls  []ControlState `json:"controls"`
	// OutOfScope counts published controls for products this console does not
	// manage, such as Teams meeting settings in the Microsoft 365 benchmark.
	OutOfScope int `json:"outOfScope,omitempty"`
	// MappingErrors names control ids this console claims but the publisher's
	// catalog does not contain. Any entry here is a bug in our mapping, not a
	// finding about the tenant.
	MappingErrors []string `json:"mappingErrors,omitempty"`
}

type Result struct {
	Overall     int                    `json:"overall"`
	Coverage    int                    `json:"coverage"`
	Enforcement int                    `json:"enforcement"`
	Fidelity    int                    `json:"fidelity"`
	Categories  []CategoryScore        `json:"categories"`
	Frameworks  []FrameworkScore       `json:"frameworks"`
	SecureScore *benchmark.SecureScore `json:"secureScore,omitempty"`
	Headline    string                 `json:"headline"`
}

// Score reads a comparison result. A policy counts as enforced only when it is
// switched on: a report-only Conditional Access policy protects nobody, so it
// counts for coverage but not for enforcement.
//
// catalogs carries the frameworks fetched from their publishers, keyed by
// framework name. A framework with no catalog is scored only against the
// templates we map to it, and its control ids cannot be validated.
func Score(cmp *engine.CompareResult, catalogs map[string]*benchmark.Catalog, secure *benchmark.SecureScore) Result {
	byCat := map[string]*CategoryScore{}

	// enforcedVia records, per framework and control, the strongest coverage we
	// can claim from a template that is actually switched on in the tenant.
	type claim struct {
		coverage string
		via      string
		note     string
		deployed bool
		enforced bool
	}
	claims := map[string]map[string]*claim{}
	declared := map[string]map[string]bool{}

	totalDeployed, totalEnforced, totalTemplates := 0, 0, 0
	driftPaths, driftedPolicies := 0, 0

	for _, it := range cmp.Items {
		cat := it.Template.Category
		cs, ok := byCat[cat]
		if !ok {
			cs = &CategoryScore{Category: cat}
			byCat[cat] = cs
		}
		cs.Total++
		totalTemplates++

		// A live policy doing the template's job under another name is deployed
		// protection. Crediting only exact names reported covered tenants as bare.
		deployed := it.State == "matches" || it.State == "drifted" || it.State == "equivalent"
		// Anything that is not a Conditional Access policy has no report-only
		// mode, so being present is being enforced.
		enforced := deployed && (it.LiveState == "" || it.LiveState == "enabled")

		// Credit the policy actually doing the work. For an equivalent that is the
		// tenant's own policy, not our template, which the tenant does not have.
		via := it.Template.Name
		if it.CoveredBy != "" {
			via = it.CoveredBy + " (tenant's own policy, does the job of " + templateLabel(it.Template) + ")"
		}
		for _, c := range loaded.Templates[it.Template.ID] {
			deployed, enforced := deployed, enforced
			if c.ExactOnly && it.State == "equivalent" && !it.Exact {
				// Covered only by something broader: true for the template, not for
				// a control that asks for this specific kind of policy.
				deployed, enforced = false, false
			}
			if declared[c.Framework] == nil {
				declared[c.Framework] = map[string]bool{}
				claims[c.Framework] = map[string]*claim{}
			}
			declared[c.Framework][c.ID] = true
			cur := claims[c.Framework][c.ID]
			if cur == nil {
				cur = &claim{}
				claims[c.Framework][c.ID] = cur
			}
			cov := c.Coverage
			if cov == "" {
				cov = "full"
			}
			if enforced && (cur.coverage != "full" || !cur.enforced) {
				if !(cur.coverage == "full" && cur.enforced) {
					cur.coverage, cur.via, cur.note = cov, via, c.Note
				}
			}
			cur.deployed = cur.deployed || deployed
			cur.enforced = cur.enforced || enforced
			if cur.via == "" {
				cur.via, cur.note = via, c.Note
				if cur.coverage == "" {
					cur.coverage = cov
				}
			}
		}

		if !deployed {
			cs.Missing++
			continue
		}
		cs.Deployed++
		totalDeployed++
		if it.State == "drifted" {
			cs.Drifted++
			driftedPolicies++
			driftPaths += it.ChangeCount
		}
		if enforced {
			cs.Enforced++
			totalEnforced++
		}
	}

	out := Result{SecureScore: secure}
	for _, cs := range byCat {
		if cs.Total > 0 {
			cs.Coverage = pct(cs.Deployed, cs.Total)
		}
		out.Categories = append(out.Categories, *cs)
	}
	sort.Slice(out.Categories, func(i, j int) bool { return out.Categories[i].Category < out.Categories[j].Category })

	out.Coverage = pct(totalDeployed, totalTemplates)
	out.Enforcement = pct(totalEnforced, totalTemplates)
	// Fidelity measures how closely deployed policies still match the baseline, so
	// it is meaningless with nothing deployed. Reporting 100 there would inflate the
	// overall score for a tenant that has no protection at all.
	if totalDeployed == 0 {
		out.Fidelity = 0
	} else {
		penalty := driftPaths / 5
		if penalty > 100 {
			penalty = 100
		}
		out.Fidelity = 100 - penalty
	}
	out.Overall = (out.Coverage*40 + out.Enforcement*40 + out.Fidelity*20) / 100

	// Build one score per framework we know about, from the mapping and from the
	// publisher's catalog where we have it.
	names := map[string]bool{}
	for name := range loaded.Frameworks {
		names[name] = true
	}
	for name, cat := range catalogs {
		// An imported catalog we make no claims against and have not scoped would
		// list hundreds of "no template" lines about products this console does
		// not manage. It is listed in Settings as imported, not scored here.
		if len(declared[name]) > 0 || len(cat.Scope) > 0 || loaded.Frameworks[name] != "" {
			names[name] = true
		}
	}
	for name := range names {
		fs := FrameworkScore{
			Framework: name,
			Label:     loaded.Frameworks[name],
			Verified:  loaded.Verified[name],
		}
		cat := catalogs[name]
		if fs.Label == "" && cat != nil {
			fs.Label = cat.Label
		}
		if fs.Label == "" {
			fs.Label = name
		}
		if cat != nil {
			fs.Version, fs.Source, fs.Verified = cat.Version, cat.URL, true
		}

		// Every control the publisher lists, whether or not we cover it. A control
		// with no template is the most useful line in the report: it is a gap we
		// have nothing for at all.
		if cat != nil {
			for _, ctl := range cat.Controls {
				if !cat.InScope(ctl.ID) && claims[name][ctl.ID] == nil {
					fs.OutOfScope++
					continue
				}
				cs := ControlState{ID: ctl.ID, Title: ctl.Text, Criticality: ctl.Criticality, State: "no-template"}
				if c := claims[name][ctl.ID]; c != nil {
					cs.Via, cs.Note = c.via, c.note
					switch {
					case c.enforced && c.coverage == "full":
						cs.State = "met"
					case c.enforced:
						cs.State = "partial"
					case c.deployed:
						cs.State = "mapped-not-enforced"
					default:
						cs.State = "mapped-not-deployed"
					}
				}
				fs.Controls = append(fs.Controls, cs)
			}
			for id := range declared[name] {
				if !cat.Has(id) {
					fs.MappingErrors = append(fs.MappingErrors, id)
				}
			}
			sort.Strings(fs.MappingErrors)
		} else {
			// No catalog: score only what we declare, and say so through Verified.
			ids := make([]string, 0, len(declared[name]))
			for id := range declared[name] {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			for _, id := range ids {
				c := claims[name][id]
				cs := ControlState{ID: id, State: "mapped-not-deployed", Via: c.via, Note: c.note}
				cs.Title = titleFor(name, id)
				switch {
				case c.enforced && c.coverage == "full":
					cs.State = "met"
				case c.enforced:
					cs.State = "partial"
				case c.deployed:
					cs.State = "mapped-not-enforced"
				}
				fs.Controls = append(fs.Controls, cs)
			}
		}

		fs.Total = len(fs.Controls)
		for _, c := range fs.Controls {
			switch c.State {
			case "met":
				fs.Met++
			case "partial":
				fs.Partial++
			}
		}
		// Partial coverage counts as half a control, because claiming it in full
		// would overstate the tenant's position to a client.
		fs.Percent = pct(fs.Met*2+fs.Partial, fs.Total*2)
		out.Frameworks = append(out.Frameworks, fs)
	}
	sort.Slice(out.Frameworks, func(i, j int) bool { return out.Frameworks[i].Framework < out.Frameworks[j].Framework })

	out.Headline = headline(out, driftedPolicies)
	return out
}

// Mapped reports whether a template carries any framework claims.
func Mapped(templateID string) bool { return len(loaded.Templates[templateID]) > 0 }

func templateLabel(t catalog.Template) string {
	if t.Code != "" {
		return t.Code
	}
	return t.Name
}

func titleFor(framework, id string) string {
	for _, controls := range loaded.Templates {
		for _, c := range controls {
			if c.Framework == framework && c.ID == id && c.Title != "" {
				return c.Title
			}
		}
	}
	return ""
}

func headline(r Result, drifted int) string {
	switch {
	case r.Coverage == 0:
		return "None of the baseline is deployed in this tenant yet."
	case r.Enforcement == 0:
		return "The baseline is deployed but every policy is still report-only, so nothing is being blocked."
	case r.Coverage == 100 && drifted == 0 && r.Enforcement == 100:
		return "Fully deployed, fully enforced, and matching the baseline exactly."
	case drifted > 0:
		return "Deployed, but some policies no longer match the baseline."
	default:
		return "Partly deployed. The gaps are listed by category."
	}
}

// MappingSummary reports what this console claims to cover, without needing a
// tenant. Useful for checking the mapping itself after a catalog refresh.
func MappingSummary(catalogs map[string]*benchmark.Catalog) string {
	var b strings.Builder
	for name, cat := range catalogs {
		claimed, bad := 0, 0
		for _, controls := range loaded.Templates {
			for _, c := range controls {
				if c.Framework != name {
					continue
				}
				claimed++
				if !cat.Has(c.ID) {
					bad++
				}
			}
		}
		fmt.Fprintf(&b, "%s %s: %d controls published, %d claimed by templates, %d claimed ids not in the catalog\n",
			name, cat.Version, len(cat.Controls), claimed, bad)
	}
	return b.String()
}

func pct(a, b int) int {
	if b == 0 {
		return 0
	}
	return a * 100 / b
}
