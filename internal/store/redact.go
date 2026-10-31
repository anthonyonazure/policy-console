package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// RedactedMark starts every value that was replaced. A body containing it must
// never be written back to a tenant: the real secret is not here.
const RedactedMark = "[redacted:"

var secretName = regexp.MustCompile(`(?i)(password|passphrase|presharedkey|preshared|psk|sharedsecret|sharedkey|secret|privatekey|apikey|clientsecret)`)

// Redact replaces secret values (Wi-Fi keys, VPN shared secrets, passwords) in a
// policy body before it is stored or shown. Each is replaced by a marker that
// carries a short hash of the original, so history still shows that a secret
// CHANGED without anyone being able to read it.
//
// Two shapes are covered: a plain field whose name says it is secret, and a
// settings catalog setting whose definition id says it is secret.
func Redact(body []byte) []byte {
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return body
	}
	changed := false
	var walk func(v any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			if def, ok := x["settingDefinitionId"].(string); ok && secretName.MatchString(def) {
				if sv, ok := x["simpleSettingValue"].(map[string]any); ok {
					if s, ok := sv["value"].(string); ok && s != "" && !strings.HasPrefix(s, RedactedMark) {
						sv["value"] = mark(s)
						changed = true
					}
				}
			}
			for k, c := range x {
				if s, ok := c.(string); ok && secretName.MatchString(k) && s != "" && !strings.HasPrefix(s, RedactedMark) && !isReferenceKey(k) {
					x[k] = mark(s)
					changed = true
					continue
				}
				x[k] = walk(c)
			}
			return x
		case []any:
			for i, c := range x {
				x[i] = walk(c)
			}
			return x
		}
		return v
	}
	out := walk(doc)
	if !changed {
		return body
	}
	b, err := json.Marshal(out)
	if err != nil {
		return body
	}
	return b
}

// isReferenceKey excludes fields that merely point at a secret or describe it,
// such as the name of a secret or whether one is required.
func isReferenceKey(k string) bool {
	l := strings.ToLower(k)
	return strings.HasSuffix(l, "id") || strings.HasSuffix(l, "type") || strings.HasSuffix(l, "required") ||
		strings.HasSuffix(l, "enabled") || strings.HasSuffix(l, "name") || strings.HasSuffix(l, "length") ||
		strings.HasSuffix(l, "count") || strings.HasSuffix(l, "days")
}

func mark(s string) string {
	h := sha256.Sum256([]byte(s))
	return RedactedMark + hex.EncodeToString(h[:4]) + "]"
}

// HasRedaction reports whether a body contains a redaction marker, meaning it is
// a stored copy that must not be written back to a tenant as it is.
func HasRedaction(body []byte) bool { return strings.Contains(string(body), RedactedMark) }

// placeholderRE matches a template placeholder such as ${WIFI_KEY}.
var placeholderRE = regexp.MustCompile(`^\$\{[A-Z0-9_]+\}$`)

// FindSecrets lists the places in a body where a real looking secret is written
// out. A placeholder such as ${WIFI_KEY} is fine: it holds no secret. A shared
// template must never contain a literal one.
func FindSecrets(body []byte) []string {
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	var found []string
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch x := v.(type) {
		case map[string]any:
			if def, ok := x["settingDefinitionId"].(string); ok && secretName.MatchString(def) {
				if sv, ok := x["simpleSettingValue"].(map[string]any); ok {
					if s, ok := sv["value"].(string); ok && s != "" && !placeholderRE.MatchString(s) {
						found = append(found, path+"/"+def)
					}
				}
			}
			for k, c := range x {
				if s, ok := c.(string); ok && secretName.MatchString(k) && !isReferenceKey(k) && s != "" && !placeholderRE.MatchString(s) {
					found = append(found, path+"/"+k)
					continue
				}
				walk(path+"/"+k, c)
			}
		case []any:
			for i, c := range x {
				walk(fmt.Sprintf("%s[%d]", path, i), c)
			}
		}
	}
	walk("", doc)
	return found
}
