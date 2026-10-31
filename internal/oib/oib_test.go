package oib

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

const policy = `{"@odata.context":"x","id":"abc","createdDateTime":"2024","name":"%s","platforms":"macOS","technologies":"mdm","settingCount":1,"settings":[{"id":"0"}]}`

func write(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := []byte{0xFF, 0xFE}
	for _, c := range u {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return b
}

func tarball(t *testing.T, files map[string][]byte) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for n, b := range files {
		_ = tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(b)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func fixture(t *testing.T) string {
	root := t.TempDir()
	write(t, filepath.Join(root, "MACOS/NativeImport/a.json"), append([]byte{0xEF, 0xBB, 0xBF}, []byte(strings.Replace(policy, "%s", "Mac A", 1))...))
	write(t, filepath.Join(root, "MACOS/NativeImport/b.json"), utf16le(strings.Replace(policy, "%s", "Mac B", 1)))
	write(t, filepath.Join(root, "WINDOWS/IntuneManagement/Settings-1a1418d7.tar.gz"), tarball(t, map[string][]byte{
		"SettingsCatalog/Win One.json": []byte(strings.Replace(policy, "%s", "Win One", 1)),
		"SettingsCatalog/notes.txt":    []byte("ignore"),
		"../evil/Escape.json":          []byte(strings.Replace(policy, "%s", "../../escape", 1)),
	}))
	write(t, filepath.Join(root, "WINDOWS/IntuneManagement/UpdatePolicies/u.json"), []byte(`{"displayName":"Ring"}`))
	write(t, filepath.Join(root, "WINDOWS/IntuneManagement/CompliancePolicies/c.json"), utf16le(`{"@odata.type":"#microsoft.graph.windows10CompliancePolicy","id":"x","version":1,"displayName":"Win Compliance","scheduledActionsForRule":[{"@odata.id":"a","ruleName":null}],"assignments":[]}`))
	write(t, filepath.Join(root, "BYOD/AppProtection/ios.json"), []byte(`{"@odata.type":"#microsoft.graph.iosManagedAppProtection","id":"T_1","displayName":"iOS BYOD","deployedAppCount":37,"apps":[{"id":"a","mobileAppIdentifier":{"@odata.type":"#microsoft.graph.iosMobileAppIdentifier","bundleId":"com.x"}}]}`))
	write(t, filepath.Join(root, "WINDOWS/PolicyManifest.json"), []byte(`{"oibVersion":"4.0"}`))
	return root
}

func TestImportHandlesEncodingsTarballsAndStripsTenantFields(t *testing.T) {
	out := t.TempDir()
	sum, err := Import(fixture(t), out)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Imported["oib-macos"] != 2 {
		t.Fatalf("imported %+v", sum.Imported)
	}
	b, err := os.ReadFile(filepath.Join(out, "oib-macos", "Mac B.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"id", "createdDateTime", "@odata.context", "settingCount"} {
		if _, ok := doc[f]; ok {
			t.Errorf("%s survived into the template", f)
		}
	}
	if !strings.Contains(string(b), `"Mac B"`) {
		t.Fatal("UTF-16 file was not decoded")
	}
	if sum.Unsupported["WINDOWS/IntuneManagement/UpdatePolicies"] != 1 {
		t.Fatalf("unsupported kinds must be counted, not dropped silently: %+v", sum.Unsupported)
	}
	if sum.Imported["oib-byod"] != 1 || sum.Imported["oib-windows"] != 2 {
		t.Fatalf("compliance and app protection must import: %+v", sum.Imported)
	}
	var app map[string]any
	ab, _ := os.ReadFile(filepath.Join(out, "oib-byod", "iOS BYOD.json"))
	if err := json.Unmarshal(ab, &app); err != nil || app["deployedAppCount"] != nil || app["id"] != nil || app["apps"] == nil {
		t.Fatalf("app protection: service fields out, apps kept: %v %s", err, ab)
	}
	cb, _ := os.ReadFile(filepath.Join(out, "oib-windows", "Win Compliance.json"))
	if strings.Contains(string(cb), "@odata.id") || strings.Contains(string(cb), "assignments") || strings.Contains(string(cb), `"version"`) {
		t.Fatalf("compliance not scrubbed: %s", cb)
	}
	if sum.OIBVersion != "4.0" {
		t.Fatal(sum.OIBVersion)
	}
}

func TestNothingEscapesTheLibraryFolder(t *testing.T) {
	out := filepath.Join(t.TempDir(), "lib")
	if _, err := Import(fixture(t), out); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(out)
	entries, _ := os.ReadDir(parent)
	for _, e := range entries {
		if e.Name() != "lib" {
			t.Fatalf("wrote outside the library: %s", e.Name())
		}
	}
	if got := safeName("../../etc/passwd"); strings.ContainsAny(got, "/\\") || strings.HasPrefix(got, ".") {
		t.Fatalf("unsafe file name %q", got)
	}
}

func TestNoticeAndSummaryRecordTheLicence(t *testing.T) {
	out := t.TempDir()
	if _, err := Import(fixture(t), out); err != nil {
		t.Fatal(err)
	}
	n, _ := os.ReadFile(filepath.Join(out, "OIB-NOTICE.txt"))
	if !strings.Contains(string(n), "GNU General Public License v3.0") || !strings.Contains(string(n), SourceURL) {
		t.Fatalf("notice: %s", n)
	}
}

func TestNotAPolicyIsSkippedWithAReason(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "MACOS/NativeImport/ok.json"), []byte(strings.Replace(policy, "%s", "OK", 1)))
	write(t, filepath.Join(root, "MACOS/NativeImport/bad.json"), []byte(`{"name":"x","platforms":"macOS","settings":[]}`))
	write(t, filepath.Join(root, "MACOS/NativeImport/junk.json"), []byte(`not json`))
	sum, err := Import(root, t.TempDir())
	if err != nil || len(sum.Skipped) != 2 || sum.Imported["oib-macos"] != 1 {
		t.Fatalf("%v %+v", err, sum)
	}
}

func TestExportBookkeepingAndAssignmentsAreScrubbedAtEveryDepth(t *testing.T) {
	root := t.TempDir()
	body := `{"name":"S","platforms":"windows10","@odata.context":"x",` +
		`"@odata.id":"deviceManagement/configurationPolicies('3f2504e0-4f89-11d3-9a0c-0305e82c3301')",` +
		`"assignments@odata.associationLink":"https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('3f2504e0-4f89-11d3-9a0c-0305e82c3301')",` +
		`"#microsoft.graph.assign":{"target":"x"},` +
		`"assignments":[{"target":{"groupId":"3f2504e0-4f89-11d3-9a0c-0305e82c3301"}}],` +
		`"settings":[{"id":"0","settingDefinitions@odata.navigationLink":"x","settingInstance":{"@odata.type":"#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance","settingInstanceTemplateReference":{"settingInstanceTemplateId":"11111111-1111-1111-1111-111111111111"}}}]}`
	write(t, filepath.Join(root, "MACOS/NativeImport/s.json"), []byte(body))
	out := t.TempDir()
	sum, err := Import(root, out)
	if err != nil || len(sum.Warnings) != 0 {
		t.Fatalf("a clean template must raise no warning: %v %+v", err, sum.Warnings)
	}
	b, _ := os.ReadFile(filepath.Join(out, "oib-macos", "S.json"))
	for _, bad := range []string{"@odata.id", "associationLink", "navigationLink", "#microsoft.graph.assign", "assignments", "3f2504e0"} {
		if strings.Contains(string(b), bad) {
			t.Errorf("%s survived", bad)
		}
	}
	if !strings.Contains(string(b), "@odata.type") || !strings.Contains(string(b), "settingInstanceTemplateId") {
		t.Fatalf("the settings themselves must be intact: %s", b)
	}
}

func TestEmptyCheckoutIsAnError(t *testing.T) {
	if _, err := Import(t.TempDir(), t.TempDir()); err == nil {
		t.Fatal("a folder with no policies is not an OIB checkout")
	}
}

func TestGUIDsAreFlaggedNotSilentlyKept(t *testing.T) {
	root := t.TempDir()
	body := strings.Replace(policy, `"settings":[{"id":"0"}]`, `"settings":[{"id":"0","settingInstanceTemplateId":"11111111-1111-1111-1111-111111111111","v":"3f2504e0-4f89-11d3-9a0c-0305e82c3301"}]`, 1)
	write(t, filepath.Join(root, "MACOS/NativeImport/g.json"), []byte(strings.Replace(body, "%s", "G", 1)))
	sum, err := Import(root, t.TempDir())
	if err != nil || len(sum.Warnings) != 1 {
		t.Fatalf("%v %+v", err, sum)
	}
}
