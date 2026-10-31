// Package report writes the plain English report a client receives: what is
// protected, what is not, what changed, and what happens next. It is a pure
// function of the data it is given, so it can be tested without a tenant, and it
// escapes everything it prints because policy names come from outside.
package report

import (
	"fmt"
	"html"
	"strings"
)

// Line is one policy in a list.
type Line struct {
	Name   string
	Detail string
}

// Counts summarise a report so the next one can say what moved.
type Counts struct {
	InPlace   int `json:"inPlace"` // matches or equivalent
	Differ    int `json:"differ"`  // drifted
	Missing   int `json:"missing"`
	Excluded  int `json:"excluded"`
	Unchecked int `json:"unchecked"` // could not be read
	Critical  int `json:"openCritical"`
	Warning   int `json:"openWarning"`
}

// Data is everything a report needs.
type Data struct {
	Client    string
	Generated string
	Baseline  string
	Counts    Counts
	Previous  *Counts // the last saved report for this client, if any
	Protected []Line
	Differing []Line
	Missing   []Line
	Excluded  []Line // not expected for this client, with the reason
	Findings  []Line
	Changes   []Line // recent changes the console made
	Rollouts  []Line
	NextSteps []string
}

func esc(s string) string { return html.EscapeString(s) }

// Percent is the share of expected policies that are in place.
func (c Counts) Percent() int {
	total := c.InPlace + c.Differ + c.Missing
	if total == 0 {
		return 0
	}
	return 100 * c.InPlace / total
}

// Delta says in words how this report moved since the last one.
func Delta(now Counts, prev *Counts) string {
	if prev == nil {
		return "This is the first report for this client."
	}
	var parts []string
	if d := now.InPlace - prev.InPlace; d != 0 {
		parts = append(parts, fmt.Sprintf("%+d policies in place", d))
	}
	if d := now.Missing - prev.Missing; d != 0 {
		parts = append(parts, fmt.Sprintf("%+d missing", d))
	}
	if d := now.Differ - prev.Differ; d != 0 {
		parts = append(parts, fmt.Sprintf("%+d that differ", d))
	}
	if d := now.Critical - prev.Critical; d != 0 {
		parts = append(parts, fmt.Sprintf("%+d urgent issues", d))
	}
	if len(parts) == 0 {
		return "Nothing has changed since the last report."
	}
	return "Since the last report: " + strings.Join(parts, ", ") + "."
}

func list(title string, items []Line, empty string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<h2>%s</h2>\n", esc(title))
	if len(items) == 0 {
		fmt.Fprintf(&b, "<p class=\"muted\">%s</p>\n", esc(empty))
		return b.String()
	}
	b.WriteString("<ul>\n")
	for _, it := range items {
		if it.Detail != "" {
			fmt.Fprintf(&b, "<li><b>%s</b><br><span class=\"muted\">%s</span></li>\n", esc(it.Name), esc(it.Detail))
		} else {
			fmt.Fprintf(&b, "<li><b>%s</b></li>\n", esc(it.Name))
		}
	}
	b.WriteString("</ul>\n")
	return b.String()
}

// HTML renders the report as one self contained page.
func HTML(d Data) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">`)
	fmt.Fprintf(&b, "<title>%s security report</title>", esc(d.Client))
	b.WriteString(`<style>
:root{--ink:#1b2430;--muted:#5b6776;--line:#dde2e8;--bg:#fff;--ok:#1f8a4c;--bad:#c23b2e}
@media(prefers-color-scheme:dark){:root{--ink:#e8edf3;--muted:#9aa7b6;--line:#2a3441;--bg:#0f141b;--ok:#4ac17c;--bad:#ff7b6e}}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 -apple-system,"Segoe UI",system-ui,sans-serif}
main{max-width:760px;margin:0 auto;padding:24px 16px 60px}h1{font-size:24px;margin:0}h2{font-size:18px;margin:28px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px}
.muted{color:var(--muted)}.big{font-size:44px;font-weight:700;line-height:1}.row{display:flex;gap:24px;flex-wrap:wrap;align-items:flex-end;margin:12px 0}
li{margin:6px 0}.ok{color:var(--ok)}.bad{color:var(--bad)}
</style></head><body><main>`)
	fmt.Fprintf(&b, "<h1>%s</h1><p class=\"muted\">Security report, %s. Measured against: %s.</p>\n", esc(d.Client), esc(d.Generated), esc(d.Baseline))
	pct := d.Counts.Percent()
	cls := "ok"
	if pct < 80 {
		cls = "bad"
	}
	fmt.Fprintf(&b, "<div class=\"row\"><div><div class=\"big %s\">%d%%</div><div class=\"muted\">of the protections we expect are in place</div></div>", cls, pct)
	fmt.Fprintf(&b, "<div><div><b>%d</b> in place, <b>%d</b> differ, <b>%d</b> missing</div><div class=\"muted\">%d urgent issue(s), %d to review</div></div></div>\n",
		d.Counts.InPlace, d.Counts.Differ, d.Counts.Missing, d.Counts.Critical, d.Counts.Warning)
	fmt.Fprintf(&b, "<p>%s</p>\n", esc(Delta(d.Counts, d.Previous)))
	if d.Counts.Unchecked > 0 {
		fmt.Fprintf(&b, "<p class=\"muted\">%d item(s) could not be checked this time because access to that area has not been granted.</p>\n", d.Counts.Unchecked)
	}
	b.WriteString(list("What is protected", d.Protected, "Nothing is in place yet."))
	b.WriteString(list("What is different from our standard", d.Differing, "Nothing differs."))
	b.WriteString(list("What is missing", d.Missing, "Nothing is missing."))
	b.WriteString(list("Left out on purpose for this client", d.Excluded, "Nothing has been left out."))
	b.WriteString(list("Needs attention", d.Findings, "Nothing needs attention."))
	b.WriteString(list("Staged changes in progress", d.Rollouts, "No changes are being rolled out."))
	b.WriteString(list("Recent changes we made", d.Changes, "No recent changes."))
	if len(d.NextSteps) > 0 {
		b.WriteString("<h2>Recommended next steps</h2><ol>\n")
		for _, s := range d.NextSteps {
			fmt.Fprintf(&b, "<li>%s</li>\n", esc(s))
		}
		b.WriteString("</ol>\n")
	}
	b.WriteString("</main></body></html>")
	return b.String()
}

// NextSteps turns the counts into a short, ordered list a person can act on.
func NextSteps(c Counts) []string {
	var s []string
	if c.Critical > 0 {
		s = append(s, fmt.Sprintf("Fix the %d urgent issue(s) first: a missing or switched off sign-in protection leaves accounts exposed.", c.Critical))
	}
	if c.Missing > 0 {
		s = append(s, fmt.Sprintf("Put the %d missing protection(s) in place, starting with a small pilot group.", c.Missing))
	}
	if c.Differ > 0 {
		s = append(s, fmt.Sprintf("Review the %d policy(ies) that differ from the standard: either bring them back or record why they differ.", c.Differ))
	}
	if c.Unchecked > 0 {
		s = append(s, "Grant the console access to the areas it could not read, so the next report covers everything.")
	}
	if len(s) == 0 {
		s = append(s, "No action needed. We will check again at the next review.")
	}
	return s
}
