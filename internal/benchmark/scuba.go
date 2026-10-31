// Package benchmark keeps the console's control frameworks honest by fetching
// them from their publishers instead of trusting a hand-typed list.
//
// Two sources are automatic:
//
//   - CISA's SCuBA Microsoft 365 Secure Configuration Baselines. A US government
//     work, published openly on GitHub, versioned by release tag and structured
//     enough to parse. The console pulls the control catalog and refuses any
//     mapping that names a control the catalog does not contain.
//   - Microsoft Secure Score, read live from each tenant. It needs no mapping at
//     all, because Microsoft scores its own controls.
//
// CIS Benchmarks are deliberately not fetched. They are distributed as
// registration-gated PDFs under a license that does not permit redistribution,
// and the PDF is not machine-readable. A CIS SecureSuite member can export
// machine-readable content and drop it in as a local file instead.
package benchmark

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ScubaTag pins which published release the baselines come from. Pinning means
// an upstream edit never silently changes a client report; bumping it is a
// visible decision.
const ScubaTag = "v1.8.0"

const scubaRaw = "https://raw.githubusercontent.com/cisagov/ScubaGear/%s/PowerShell/ScubaGear/baselines/%s.md"

// scubaProducts are the baselines relevant to what this console manages:
// Entra ID (Conditional Access) and Defender.
var scubaProducts = map[string]string{
	"aad":      "Microsoft Entra ID",
	"defender": "Microsoft 365 Defender",
}

type Control struct {
	ID          string `json:"id"`      // e.g. MS.AAD.1.1v1
	Product     string `json:"product"` // aad | defender
	ProductName string `json:"productName"`
	Section     string `json:"section"`     // the numbered heading it sits under
	Criticality string `json:"criticality"` // SHALL | SHOULD | MAY
	Text        string `json:"text"`        // the requirement, as published
}

type Catalog struct {
	Source    string    `json:"source"`
	Label     string    `json:"label,omitempty"`
	Scope     []string  `json:"scope,omitempty"` // section prefixes this console scores; empty means all
	Version   string    `json:"version"`
	FetchedAt time.Time `json:"fetchedAt"`
	URL       string    `json:"url"`
	Controls  []Control `json:"controls"`
	Notes     string    `json:"notes"`
}

func (c *Catalog) Has(id string) bool {
	for _, ctl := range c.Controls {
		if strings.EqualFold(ctl.ID, id) {
			return true
		}
	}
	return false
}

func (c *Catalog) Control(id string) *Control {
	for i, ctl := range c.Controls {
		if strings.EqualFold(ctl.ID, id) {
			return &c.Controls[i]
		}
	}
	return nil
}

var (
	// #### MS.AAD.1.1v1
	controlHeadingRE = regexp.MustCompile(`(?m)^####\s+(MS\.[A-Z]+\.\d+\.\d+v\d+)\s*$`)
	// <!--Policy: MS.AAD.1.1v1; Criticality: SHALL -->
	criticalityRE = regexp.MustCompile(`<!--\s*Policy:\s*(MS\.[A-Z]+\.\d+\.\d+v\d+)\s*;\s*Criticality:\s*([A-Z/]+)\s*-->`)
	// ## 1. Legacy Authentication
	sectionRE = regexp.MustCompile(`(?m)^##\s+(\d+\.\s+.+)$`)
)

// FetchScuba downloads and parses the SCuBA baselines for the products this
// console manages.
func FetchScuba(ctx context.Context, client *http.Client) (*Catalog, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	cat := &Catalog{
		Source:    "scuba",
		Version:   ScubaTag,
		FetchedAt: time.Now().UTC(),
		URL:       "https://github.com/cisagov/ScubaGear/tree/" + ScubaTag + "/PowerShell/ScubaGear/baselines",
		Notes:     "CISA M365 Secure Configuration Baselines, pinned to release " + ScubaTag + ". Public domain US government work.",
	}
	products := make([]string, 0, len(scubaProducts))
	for p := range scubaProducts {
		products = append(products, p)
	}
	sort.Strings(products)

	for _, product := range products {
		url := fmt.Sprintf(scubaRaw, ScubaTag, product)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetch %s baseline: %w", product, err)
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetch %s baseline: %s returned %d", product, url, resp.StatusCode)
		}
		if readErr != nil {
			return nil, readErr
		}
		cat.Controls = append(cat.Controls, parseScuba(product, string(body))...)
	}
	if len(cat.Controls) == 0 {
		return nil, fmt.Errorf("baselines fetched but no controls parsed; the upstream format may have changed")
	}
	sort.Slice(cat.Controls, func(i, j int) bool { return cat.Controls[i].ID < cat.Controls[j].ID })
	return cat, nil
}

// parseScuba pulls one control per "#### MS.X.n.mvK" heading, taking the
// requirement text that follows and the criticality from the policy comment.
func parseScuba(product, doc string) []Control {
	crit := map[string]string{}
	for _, m := range criticalityRE.FindAllStringSubmatch(doc, -1) {
		crit[m[1]] = m[2]
	}

	// Map each byte offset to the section heading in force at that point.
	type marker struct {
		at   int
		name string
	}
	var sections []marker
	for _, loc := range sectionRE.FindAllStringSubmatchIndex(doc, -1) {
		sections = append(sections, marker{at: loc[0], name: strings.TrimSpace(doc[loc[2]:loc[3]])})
	}
	sectionAt := func(offset int) string {
		name := ""
		for _, s := range sections {
			if s.at < offset {
				name = s.name
			}
		}
		return name
	}

	var out []Control
	matches := controlHeadingRE.FindAllStringSubmatchIndex(doc, -1)
	for i, loc := range matches {
		id := doc[loc[2]:loc[3]]
		start := loc[1]
		end := len(doc)
		if i+1 < len(matches) {
			end = matches[i+1][0]
		}
		body := doc[start:end]

		// The requirement is the first prose paragraph; the Instructions sections
		// repeat the same headings later, so those repeats carry no comment and
		// are skipped by keeping the first occurrence only.
		text := firstParagraph(body)
		if text == "" {
			continue
		}
		if seen(out, id) {
			continue
		}
		out = append(out, Control{
			ID:          id,
			Product:     product,
			ProductName: scubaProducts[product],
			Section:     sectionAt(loc[0]),
			Criticality: crit[id],
			Text:        text,
		})
	}
	return out
}

func seen(list []Control, id string) bool {
	for _, c := range list {
		if c.ID == id {
			return true
		}
	}
	return false
}

func firstParagraph(body string) string {
	var buf []string
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			if len(buf) > 0 {
				break
			}
			continue
		}
		if strings.HasPrefix(trimmed, "<!--") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		buf = append(buf, trimmed)
	}
	text := strings.Join(buf, " ")
	text = strings.TrimSpace(strings.TrimPrefix(text, "-"))
	if len(text) > 600 {
		text = text[:600] + "..."
	}
	return text
}

func (c *Catalog) MarshalCache() ([]byte, error) { return json.Marshal(c) }

func Unmarshal(raw []byte) (*Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
