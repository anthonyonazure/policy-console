package benchmark

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// CIS Benchmarks cannot be downloaded or redistributed, but a licensed copy
// can be read for internal use. The importer reads the PDFs the operator
// already holds and stores the parsed catalog in the console's own database
// only. Nothing from a CIS PDF is ever written into the repository.

// cisScopes limits scoring to the sections this console actually manages, so a
// Conditional Access console is not marked down for Teams meeting settings.
// Controls outside scope are still imported and counted, just not scored.
var cisScopes = map[string][]string{
	"cis-m365": {"5.2.2"},
}

// cisSourceName turns a benchmark file name into a stable source key.
func cisSourceName(file string) (key, label string) {
	base := strings.TrimSuffix(filepath.Base(file), filepath.Ext(file))
	label = strings.ReplaceAll(base, "_", " ")
	lower := strings.ToLower(base)
	switch {
	case strings.Contains(lower, "microsoft_365_foundations"):
		return "cis-m365", label
	}
	// The version is dropped from the key so importing v6 replaces v5 rather
	// than scoring a tenant against both.
	lower = regexp.MustCompile(`[_ ]v\d+(\.\d+)*.*$`).ReplaceAllString(lower, "")
	lower = strings.TrimSuffix(strings.TrimSuffix(lower, "_benchmark"), " benchmark")
	slug := strings.Trim(regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(lower, "-"), "-")
	return "cis-" + strings.TrimPrefix(slug, "cis-"), label
}

var (
	cisVersionRE = regexp.MustCompile(`(?i)[_ ]v(\d+\.\d+\.\d+)`)
	// A recommendation heading: "5.2.2.1 Ensure ...".
	cisHeadRE  = regexp.MustCompile(`^(\d+(?:\.\d+)+)\s+(\S.*)$`)
	cisTailRE  = regexp.MustCompile(`\((Automated|Manual)\)\s*$`)
	cisLevelRE = regexp.MustCompile(`^\s*[•\-]\s*(.*Level\s+\d.*)$`)
)

// ParseCIS reads the text of one CIS benchmark and returns its
// recommendations. It relies on every recommendation in the body being
// followed by a "Profile Applicability:" block, which is what separates the
// body from the table of contents.
func ParseCIS(text string) []Control {
	// pdftotext starts every page with a form feed, which lands directly in
	// front of any recommendation that begins a page and hides its number.
	lines := strings.Split(strings.ReplaceAll(text, "\f", ""), "\n")
	var out []Control
	seen := map[string]bool{}
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "Profile Applicability:" {
			continue
		}
		// Walk back to the heading; titles wrap over up to three lines.
		title := ""
		id := ""
		for j := i - 1; j >= 0 && j >= i-4; j-- {
			// Only lines just above a "Profile Applicability:" block are read, so
			// the table of contents never reaches here and indentation, which
			// varies between benchmarks, does not matter.
			raw := strings.TrimSpace(lines[j])
			if raw == "" {
				continue
			}
			if m := cisHeadRE.FindStringSubmatch(raw); m != nil {
				id = m[1]
				title = strings.TrimSpace(m[2] + " " + title)
				break
			}
			title = strings.TrimSpace(raw + " " + title)
		}
		if id == "" || seen[id] {
			continue
		}
		mode := ""
		if m := cisTailRE.FindStringSubmatch(title); m != nil {
			mode = m[1]
			title = strings.TrimSpace(cisTailRE.ReplaceAllString(title, ""))
		}
		var levels []string
		for k := i + 1; k < len(lines) && k < i+10; k++ {
			l := strings.TrimSpace(lines[k])
			if strings.HasPrefix(l, "Description") {
				break
			}
			if m := cisLevelRE.FindStringSubmatch(lines[k]); m != nil {
				levels = append(levels, strings.TrimSpace(m[1]))
			}
		}
		seen[id] = true
		crit := strings.Join(levels, ", ")
		if mode != "" {
			crit = strings.TrimSpace(crit + " (" + mode + ")")
		}
		out = append(out, Control{ID: id, Text: title, Criticality: crit, Section: sectionOf(id)})
	}
	sort.Slice(out, func(i, j int) bool { return versionLess(out[i].ID, out[j].ID) })
	return out
}

func sectionOf(id string) string {
	if i := strings.LastIndex(id, "."); i > 0 {
		return id[:i]
	}
	return id
}

// versionLess orders 5.2.2.2 before 5.2.2.10.
func versionLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if pa[i] == pb[i] {
			continue
		}
		var x, y int
		fmt.Sscan(pa[i], &x)
		fmt.Sscan(pb[i], &y)
		return x < y
	}
	return len(pa) < len(pb)
}

// InScope reports whether a control belongs to a section this console scores.
func (c *Catalog) InScope(id string) bool {
	if len(c.Scope) == 0 {
		return true
	}
	for _, p := range c.Scope {
		if id == p || strings.HasPrefix(id, p+".") {
			return true
		}
	}
	return false
}

// ImportCIS parses every CIS benchmark PDF in a folder. It needs pdftotext
// (poppler) on the machine running the import; the parsed catalog is then
// stored in the database, so a server never needs the PDFs or the tool.
func ImportCIS(ctx context.Context, dir string) ([]*Catalog, error) {
	tool, err := exec.LookPath("pdftotext")
	if err != nil {
		return nil, fmt.Errorf("pdftotext is not installed on this machine (brew install poppler, or apt install poppler-utils); import on a machine that has it and the catalog travels in the database")
	}
	// Walk subfolders too: some benchmarks arrive as a folder of their own.
	var files []string
	err = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.EqualFold(filepath.Ext(p), ".pdf") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no PDF files in %s", dir)
	}
	var out []*Catalog
	for _, f := range files {
		if !strings.HasPrefix(strings.ToUpper(filepath.Base(f)), "CIS") {
			continue
		}
		cmd := exec.CommandContext(ctx, tool, "-layout", f, "-")
		var buf, errBuf bytes.Buffer
		cmd.Stdout, cmd.Stderr = &buf, &errBuf
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("reading %s: %v %s", filepath.Base(f), err, errBuf.String())
		}
		controls := ParseCIS(buf.String())
		if len(controls) == 0 {
			return nil, fmt.Errorf("%s parsed to zero recommendations; the layout may have changed", filepath.Base(f))
		}
		key, label := cisSourceName(f)
		version := ""
		if m := cisVersionRE.FindStringSubmatch(filepath.Base(f)); m != nil {
			version = "v" + m[1]
		}
		info, _ := os.Stat(f)
		note := "Parsed from the licensed copy at " + f + ". Stored in this console's database only; not redistributed."
		if info != nil {
			note += " File dated " + info.ModTime().Format("2006-01-02") + "."
		}
		out = append(out, &Catalog{
			Source:    key,
			Label:     label,
			Version:   version,
			FetchedAt: time.Now().UTC(),
			URL:       "local: " + filepath.Base(f),
			Controls:  controls,
			Scope:     cisScopes[key],
			Notes:     note,
		})
	}
	return out, nil
}
