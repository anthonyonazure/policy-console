// Package oib imports Open Intune Baseline settings catalog policies into a
// local template library the console can load.
//
// Open Intune Baseline is licensed GPL-3.0. The console therefore does not ship
// it inside the program: the import writes to a folder on the operator's
// machine, with the licence and source recorded beside the files, and the
// console reads that folder at start up. Keep that folder out of the repository.
package oib

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"
)

// Source repository, recorded in the attribution file.
const SourceURL = "https://github.com/SkipToTheEndpoint/OpenIntuneBaseline"

var guidRE = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

// oibIDRE matches OIB's stable policy id as written in each description.
var oibIDRE = regexp.MustCompile(`OIBID:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

// Summary says what an import did, including what it deliberately left out.
type Summary struct {
	OIBVersion  string         `json:"oibVersion,omitempty"`
	Imported    map[string]int `json:"imported"`          // library folder -> files written
	Skipped     []Skip         `json:"skipped,omitempty"` // files not importable, with the reason
	Unsupported map[string]int `json:"unsupported"`       // kinds of policy the console cannot manage yet, by OIB folder
	Warnings    []string       `json:"warnings,omitempty"`
}

type Skip struct {
	File   string `json:"file"`
	Reason string `json:"reason"`
}

// sources lists where settings catalog policies live in an OIB checkout.
type source struct {
	library string // output folder name
	dir     string // relative to the OIB root
	tarball string // when set, read this archive's SettingsCatalog/ entries instead of a folder
}

var sources = []source{
	{library: "oib-macos", dir: "MACOS/NativeImport"},
	{library: "oib-windows365", dir: "WINDOWS365/NativeImport"},
	{library: "oib-windows", tarball: "WINDOWS/IntuneManagement/Settings-1a1418d7.tar.gz"},
	{library: "oib-windows", dir: "WINDOWS/IntuneManagement/SettingsCatalog"},
	{library: "oib-windows", dir: "WINDOWS/IntuneManagement/CompliancePolicies"},
	{library: "oib-macos", dir: "MACOS/IntuneManagement/CompliancePolicies"},
	{library: "oib-windows365", dir: "WINDOWS365/IntuneManagement/CompliancePolicies"},
	{library: "oib-byod", dir: "BYOD/AppProtection"},
}

// unsupportedDirs are OIB content the console cannot yet read, compare or
// deploy. They are counted so the operator can see what is missing.
var unsupportedDirs = []string{
	"WINDOWS/IntuneManagement/UpdatePolicies",
	"WINDOWS/IntuneManagement/DriverUpdateProfiles",
	"WINDOWS/IntuneManagement/DeviceConfiguration",
}

// Import reads an OIB checkout at root and writes the library under out.
func Import(root, out string) (*Summary, error) {
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("%s is not a folder", root)
	}
	sum := &Summary{Imported: map[string]int{}, Unsupported: map[string]int{}}
	seen := map[string]bool{} // library|name, so a policy in two places is written once

	write := func(library, file string, raw []byte) {
		body, name, err := normalize(raw)
		if err != nil {
			sum.Skipped = append(sum.Skipped, Skip{File: file, Reason: err.Error()})
			return
		}
		key := library + "|" + strings.ToLower(name)
		if seen[key] {
			return
		}
		seen[key] = true
		if n := foreignGUIDs(body); n > 0 {
			sum.Warnings = append(sum.Warnings, fmt.Sprintf("%s has %d GUID(s) outside Microsoft's template reference fields; confirm they are not a tenant's object ids", file, n))
		}
		dir := filepath.Join(out, library)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			sum.Skipped = append(sum.Skipped, Skip{File: file, Reason: err.Error()})
			return
		}
		if err := os.WriteFile(filepath.Join(dir, safeName(name)+".json"), body, 0o644); err != nil {
			sum.Skipped = append(sum.Skipped, Skip{File: file, Reason: err.Error()})
			return
		}
		sum.Imported[library]++
	}

	for _, s := range sources {
		switch {
		case s.tarball != "":
			p := filepath.Join(root, s.tarball)
			if _, err := os.Stat(p); err != nil {
				continue
			}
			if err := eachInTarball(p, "SettingsCatalog/", func(name string, raw []byte) { write(s.library, name, raw) }); err != nil {
				sum.Skipped = append(sum.Skipped, Skip{File: s.tarball, Reason: err.Error()})
			}
		default:
			entries, err := os.ReadDir(filepath.Join(root, s.dir))
			if err != nil {
				continue
			}
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
					continue
				}
				raw, err := os.ReadFile(filepath.Join(root, s.dir, e.Name()))
				if err != nil {
					sum.Skipped = append(sum.Skipped, Skip{File: filepath.Join(s.dir, e.Name()), Reason: err.Error()})
					continue
				}
				write(s.library, filepath.Join(s.dir, e.Name()), raw)
			}
		}
	}

	for _, d := range unsupportedDirs {
		if entries, err := os.ReadDir(filepath.Join(root, d)); err == nil {
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
					sum.Unsupported[d]++
				}
			}
		}
	}
	sum.OIBVersion = oibVersion(root)

	if len(sum.Imported) == 0 {
		return sum, fmt.Errorf("found no settings catalog policies under %s; is it an Open Intune Baseline checkout?", root)
	}
	if err := writeSidecars(out, sum); err != nil {
		return sum, err
	}
	sort.Slice(sum.Skipped, func(i, j int) bool { return sum.Skipped[i].File < sum.Skipped[j].File })
	return sum, nil
}

func oibVersion(root string) string {
	b, err := os.ReadFile(filepath.Join(root, "WINDOWS", "PolicyManifest.json"))
	if err != nil {
		return ""
	}
	var m struct {
		V string `json:"oibVersion"`
	}
	_ = json.Unmarshal(b, &m)
	return m.V
}

func writeSidecars(out string, sum *Summary) error {
	note := fmt.Sprintf(`These policies come from Open Intune Baseline (version %s).
Source: %s
Licence: GNU General Public License v3.0. Keep this notice with the files.

They were converted to plain UTF-8 JSON and stripped of tenant-assigned fields. Settings are unchanged.
This folder is a local library: do not commit it to the console's repository and do not embed it in the program.
`, orUnknown(sum.OIBVersion), SourceURL)
	if err := os.WriteFile(filepath.Join(out, "OIB-NOTICE.txt"), []byte(note), 0o644); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(sum, "", "  ")
	// The summary sits outside the library folders so the console never tries to load it as a template.
	return os.WriteFile(filepath.Join(out, "oib-import-summary.txt"), b, 0o644)
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// readOnly are fields Microsoft assigns; they mean nothing in a template.
var readOnly = []string{"id", "createdDateTime", "lastModifiedDateTime", "modifiedDateTime", "@odata.context", "settingCount", "creationSource", "priorityMetaData", "isAssigned"}

// normalize decodes whatever text encoding the file uses, checks it is a
// settings catalog policy, and removes tenant-assigned fields.
func normalize(raw []byte) (body []byte, name string, err error) {
	text, err := decodeText(raw)
	if err != nil {
		return nil, "", err
	}
	var doc map[string]any
	if err := json.Unmarshal(text, &doc); err != nil {
		return nil, "", fmt.Errorf("not valid JSON: %v", err)
	}
	if ot, _ := doc["@odata.type"].(string); isCompliance(ot) || isAppProtection(ot) {
		// Compliance and app protection policies are named by displayName and are
		// not settings catalog policies.
		name, _ = doc["displayName"].(string)
		if name == "" {
			return nil, "", fmt.Errorf("no policy name")
		}
		for _, f := range append(readOnly, "version", "deployedAppCount") {
			delete(doc, f)
		}
		scrub(doc)
		body, err = json.MarshalIndent(doc, "", "  ")
		return body, name, err
	}
	name, _ = doc["name"].(string)
	if name == "" {
		return nil, "", fmt.Errorf("no policy name")
	}
	if _, ok := doc["platforms"].(string); !ok {
		return nil, "", fmt.Errorf("not a settings catalog policy (no platforms)")
	}
	if s, ok := doc["settings"].([]any); !ok || len(s) == 0 {
		return nil, "", fmt.Errorf("not a settings catalog policy (no settings)")
	}
	for _, f := range readOnly {
		delete(doc, f)
	}
	scrub(doc)
	body, err = json.MarshalIndent(doc, "", "  ")
	return body, name, err
}

// decodeText handles the three encodings found in OIB exports: UTF-8 with or
// without a byte order mark, and UTF-16 in either byte order.
func decodeText(b []byte) ([]byte, error) {
	switch {
	case bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}):
		return b[3:], nil
	case bytes.HasPrefix(b, []byte{0xFF, 0xFE}):
		return utf16Bytes(b[2:], binary.LittleEndian), nil
	case bytes.HasPrefix(b, []byte{0xFE, 0xFF}):
		return utf16Bytes(b[2:], binary.BigEndian), nil
	}
	return b, nil
}

func utf16Bytes(b []byte, order binary.ByteOrder) []byte {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, order.Uint16(b[i:]))
	}
	return []byte(string(utf16.Decode(u)))
}

// scrub removes, at every depth, what an export carries that a template must not:
// OData bookkeeping (links that embed the exporting tenant's policy id), action
// metadata, and any exported assignments. A template is unassigned by design;
// where it is assigned is decided per client.
func scrub(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			switch {
			case k == "assignments", strings.HasPrefix(k, "#microsoft.graph."):
				delete(x, k)
			case strings.Contains(k, "@odata.") && k != "@odata.type":
				delete(x, k)
			default:
				scrub(c)
			}
		}
	case []any:
		for _, c := range x {
			scrub(c)
		}
	}
}

func eachInTarball(path, prefix string, fn func(name string, raw []byte)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		// Only regular files under the expected folder; a crafted path must not matter
		// because nothing is extracted by name, content is read in memory.
		if h.Typeflag != tar.TypeReg || !strings.HasPrefix(h.Name, prefix) || !strings.HasSuffix(strings.ToLower(h.Name), ".json") {
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(tr, 8<<20))
		if err != nil {
			return err
		}
		fn(h.Name, raw)
	}
}

var unsafeRE = regexp.MustCompile(`[^A-Za-z0-9 ._()\-]+`)

// safeName turns a policy name into a file name. Names come from files we do
// not control, so nothing path-like may survive.
func safeName(n string) string {
	n = strings.TrimSpace(unsafeRE.ReplaceAllString(n, "_"))
	n = strings.Trim(n, ".")
	if n == "" {
		n = "policy"
	}
	return n
}

// foreignGUIDs counts GUIDs that are not Microsoft's own template references.
// Every settings catalog policy carries many of those (settingInstanceTemplateId
// and similar) and they identify Microsoft's templates, not anyone's tenant. A
// GUID anywhere else may be a group or object id from a real tenant, which must
// never reach a shared template.
func foreignGUIDs(body []byte) int {
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return 0
	}
	var walk func(key string, v any) int
	walk = func(key string, v any) int {
		switch x := v.(type) {
		case map[string]any:
			n := 0
			for k, c := range x {
				n += walk(k, c)
			}
			return n
		case []any:
			n := 0
			for _, c := range x {
				n += walk(key, c)
			}
			return n
		case string:
			if strings.Contains(strings.ToLower(key), "template") {
				return 0
			}
			// OIB's own stable policy id ("OIBID:<guid>") and Microsoft's public
			// Office update channel addresses are not anyone's tenant.
			x = oibIDRE.ReplaceAllString(x, "")
			if strings.HasPrefix(x, "https://officecdn.microsoft.com/") {
				return 0
			}
			return len(guidRE.FindAllString(x, -1))
		}
		return 0
	}
	return walk("", doc)
}

func isCompliance(odataType string) bool {
	return strings.HasSuffix(strings.ToLower(odataType), "compliancepolicy")
}

func isAppProtection(odataType string) bool {
	t := strings.ToLower(odataType)
	return strings.HasSuffix(t, "managedappprotection") && (strings.Contains(t, "ios") || strings.Contains(t, "android"))
}
