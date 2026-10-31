package store

import (
	"strings"
	"testing"
)

func TestSecretsAreReplacedButAChangedSecretStillShowsAsAChange(t *testing.T) {
	a := Redact([]byte(`{"name":"Wi-Fi","preSharedKey":"hunter2","passwordRequired":true,"minPasswordLength":8,"nested":{"clientSecret":"abc"}}`))
	b := Redact([]byte(`{"name":"Wi-Fi","preSharedKey":"hunter3","passwordRequired":true,"minPasswordLength":8,"nested":{"clientSecret":"abc"}}`))
	if strings.Contains(string(a), "hunter2") || strings.Contains(string(a), `"abc"`) {
		t.Fatalf("a secret survived: %s", a)
	}
	if !strings.Contains(string(a), `"passwordRequired":true`) || !strings.Contains(string(a), `"minPasswordLength":8`) {
		t.Fatalf("a setting ABOUT passwords is not a secret and must stay readable: %s", a)
	}
	if string(a) == string(b) {
		t.Fatal("a changed secret must still change the stored body, or drift detection goes blind")
	}
	if !HasRedaction(a) {
		t.Fatal("HasRedaction")
	}
	if again := Redact(a); string(again) != string(a) {
		t.Fatal("redacting twice must not change anything")
	}
}

func TestSettingsCatalogSecretsAreFoundByTheirDefinition(t *testing.T) {
	body := `{"settings":[{"settingInstance":{"settingDefinitionId":"vendor_msft_wifi_psk","simpleSettingValue":{"value":"correct horse"}}},
	 {"settingInstance":{"settingDefinitionId":"device_vendor_msft_policy_config_timezone","simpleSettingValue":{"value":"Pacific"}}}]}`
	out := string(Redact([]byte(body)))
	if strings.Contains(out, "correct horse") || !strings.Contains(out, "Pacific") {
		t.Fatalf("%s", out)
	}
}

func TestSaveVersionNeverStoresASecret(t *testing.T) {
	db := openDrift(t)
	_, _, err := db.SaveVersion(Version{TenantID: "t", Kind: "configuration-policies", ObjectID: "p", Name: "Wi-Fi", Source: "manual", Body: []byte(`{"password":"s3cret"}`)})
	if err != nil {
		t.Fatal(err)
	}
	v, _ := db.History("t", "configuration-policies", "p")
	if len(v) != 1 || strings.Contains(string(v[0].Body), "s3cret") {
		t.Fatalf("%+v", v)
	}
}
