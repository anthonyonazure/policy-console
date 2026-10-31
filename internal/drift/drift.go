// Package drift turns a comparison of one client against the standard into a
// short list of findings a person can act on: what is missing, what changed,
// what was switched off, and what exists that the standard does not know about.
// It decides severity and applies approved exceptions; it never talks to Graph.
package drift

import (
	"fmt"
	"strings"
	"time"

	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/engine"
	"github.com/anthonyonazure/policy-console/internal/store"
)

const (
	Critical = "critical"
	Warning  = "warning"
	Info     = "info"

	ClassMissing  = "missing"
	ClassChanged  = "changed"
	ClassDisabled = "disabled"
	ClassExtra    = "extra"
)

// Result is the outcome of evaluating one comparison.
type Result struct {
	Findings   []store.Finding
	Excepted   int // findings silenced by an active exception
	Unchecked  int // templates that could not be compared because the client's values are not filled in
	UncheckedN []string
	// UncheckedIDs are the template ids that could not be judged. Findings already
	// open for them must be kept, not resolved: not looking is not the same as fixed.
	UncheckedIDs []string
}

// ExtraID is the exception key for a live object the standard does not know about.
func ExtraID(kind, objectID string) string { return "extra:" + kind + ":" + objectID }

// Evaluate classifies every template and unmanaged object in cmp. Templates
// that could not be rendered (an unfilled client value) are reported as
// unchecked rather than as drift, because silence would hide them and an alarm
// would blame the client for our missing input.
func Evaluate(cmp *engine.CompareResult, exceptions []store.Exception, now time.Time) Result {
	silenced := map[string]bool{}
	for _, e := range exceptions {
		if e.Active(now) {
			silenced[e.TemplateID] = true
		}
	}
	var res Result
	add := func(f store.Finding) {
		if silenced[f.TemplateID] {
			res.Excepted++
			return
		}
		res.Findings = append(res.Findings, f)
	}

	for _, it := range cmp.Items {
		t := it.Template
		isCA := t.Kind == catalog.KindConditionalAccess
		switch it.State {
		case "error":
			res.Unchecked++
			res.UncheckedN = append(res.UncheckedN, t.Name)
			res.UncheckedIDs = append(res.UncheckedIDs, t.ID)
		case "missing":
			add(store.Finding{TemplateID: t.ID, Class: ClassMissing, Severity: severity(t.Kind, ClassMissing), Name: t.Name,
				Detail: "In the standard but not found in this tenant."})
		case "drifted":
			class := ClassChanged
			if isCA && it.LiveState == "disabled" {
				class = ClassDisabled
			}
			add(store.Finding{TemplateID: t.ID, Class: class, Severity: severity(t.Kind, class), Name: t.Name, Detail: describeChanges(it)})
		case "matches", "equivalent":
			if isCA && it.LiveState == "disabled" {
				add(store.Finding{TemplateID: t.ID, Class: ClassDisabled, Severity: severity(t.Kind, ClassDisabled), Name: t.Name,
					Detail: "The policy exists but is switched off, so it protects nobody."})
			}
		}
	}

	for _, u := range cmp.Unmanaged {
		add(store.Finding{TemplateID: ExtraID(u.Kind, u.ObjectID), Class: ClassExtra, Severity: Info, Name: u.Name,
			Detail: "In the tenant but not part of the standard."})
	}
	return res
}

// severity encodes what hurts. Conditional Access is the front door: a missing
// or switched-off policy there is urgent. Everything else that departs from the
// standard is worth a look but not an interruption.
func severity(kind catalog.Kind, class string) string {
	switch {
	case kind == catalog.KindConditionalAccess && (class == ClassMissing || class == ClassDisabled):
		return Critical
	case kind == catalog.KindCompliance && class == ClassMissing:
		return Critical // devices stop being judged at all
	case class == ClassExtra:
		return Info
	default:
		return Warning
	}
}

func describeChanges(it engine.TemplateStatus) string {
	if len(it.Changes) == 0 {
		return "Differs from the standard."
	}
	var paths []string
	for i, c := range it.Changes {
		if i == 3 {
			paths = append(paths, fmt.Sprintf("and %d more", len(it.Changes)-3))
			break
		}
		paths = append(paths, c.Path)
	}
	return fmt.Sprintf("%d setting(s) differ from the standard: %s.", len(it.Changes), strings.Join(paths, ", "))
}
