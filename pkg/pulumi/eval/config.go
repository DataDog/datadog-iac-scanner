/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package eval

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/pulumi/placeholders/schemagen"
)

// providerDefaults are provider settings a CI stack normally defines. They are
// given to the program when the stack does not set them, and listed as such.
var providerDefaults = map[string]string{
	"aws:region":            schemagen.Region["aws"],
	"gcp:project":           schemagen.GCPProject,
	"gcp:region":            schemagen.Region["gcp"],
	"gcp:zone":              schemagen.Region["gcp"] + "-a",
	"azure:location":        schemagen.Region["azure"],
	"azure:environment":     "public",
	"azure:subscriptionId":  schemagen.GUID,
	"azure-native:location": schemagen.Region["azure"],
}

// Configuration value and accessor type names.
const (
	valueTrue  = "true"
	valueFalse = "false"
	typeObject = "object"
	typeFloat  = "float"
)

// secretPlaceholder is the value of a secure stack setting: it cannot be
// decrypted, and the program receives it as a secret.
const secretPlaceholder = "dd-secret-placeholder"

// genericCandidates are tried, in order, when the program rejects a value.
var genericCandidates = []string{schemagen.Text, "1", valueTrue, "[]", "{}"}

// stackConfig is the configuration given to a program, and where it came from.
type stackConfig struct {
	values           map[string]string
	secrets          map[string]bool
	placeholders     map[string]bool
	providerDefaults map[string]bool
	tried            map[string]int // index of the candidate in use, per key
}

func newStackConfig(p *Project, st *Stack, src *sourceIndex) *stackConfig {
	c := &stackConfig{
		values:           map[string]string{},
		secrets:          map[string]bool{},
		placeholders:     map[string]bool{},
		providerDefaults: map[string]bool{},
		tried:            map[string]int{},
	}
	for k, v := range providerDefaults {
		c.values[k] = v
		c.providerDefaults[k] = true
	}
	for key, spec := range p.Config {
		c.setProjectKey(qualify(key, p.Name), spec, src)
	}
	for key, value := range st.Config {
		k := qualify(key, p.Name)
		delete(c.providerDefaults, k)
		delete(c.placeholders, k)
		value, secure := redactSecure(value)
		if secure {
			c.secrets[k] = true
		}
		c.values[k] = encodeConfig(value)
	}
	return c
}

// redactSecure replaces every encrypted value ({secure: ...}) in a stack
// setting by a placeholder. Pulumi writes them at the top level or, for
// `pulumi config set --path --secret`, nested in objects and lists; the whole
// setting is then secret. As in Pulumi, an encrypted value is an object whose
// only key is secure, with a string. It reports whether there was one.
func redactSecure(v any) (any, bool) {
	switch t := v.(type) {
	case map[string]any:
		if _, ok := t["secure"].(string); ok && len(t) == 1 {
			return secretPlaceholder, true
		}
		out, found := make(map[string]any, len(t)), false
		for k, e := range t {
			var secure bool
			out[k], secure = redactSecure(e)
			found = found || secure
		}
		return out, found
	case []any:
		out, found := make([]any, len(t)), false
		for i, e := range t {
			var secure bool
			out[i], secure = redactSecure(e)
			found = found || secure
		}
		return out, found
	}
	return v, false
}

// setProjectKey applies one entry of the config block of Pulumi.yaml: a plain
// value, or a declaration with type, default, value and secret.
func (c *stackConfig) setProjectKey(k string, spec any, src *sourceIndex) {
	delete(c.providerDefaults, k)
	decl, ok := spec.(map[string]any)
	if !ok {
		c.values[k] = encodeConfig(spec)
		return
	}
	if secret, _ := decl["secret"].(bool); secret {
		c.secrets[k] = true
	}
	if v, ok := decl["value"]; ok && v != nil && v != "" {
		c.values[k] = encodeConfig(v)
		return
	}
	if v, ok := decl["default"]; ok {
		c.values[k] = encodeConfig(v)
		return
	}
	// Declared without a value: a placeholder of the declared type, or typed
	// from how the program reads it.
	declared, _ := decl["type"].(string)
	switch declared {
	case "integer":
		c.values[k] = "1"
	case "boolean":
		c.values[k] = valueFalse
	case "array":
		c.values[k] = "[]"
	case typeObject:
		c.values[k] = "{}"
	default:
		c.values[k] = candidatesFor(k, src)[0]
	}
	c.placeholders[k] = true
}

// addPlaceholder gives a missing key its first candidate value.
func (c *stackConfig) addPlaceholder(key string, src *sourceIndex) {
	c.values[key] = candidatesFor(key, src)[0]
	c.tried[key] = 0
	c.placeholders[key] = true
	delete(c.providerDefaults, key)
}

// nextCandidate replaces a rejected placeholder by the next candidate. It
// returns false when there is none left.
func (c *stackConfig) nextCandidate(key string, src *sourceIndex) bool {
	cands := candidatesFor(key, src)
	i := c.tried[key] + 1
	if i >= len(cands) {
		return false
	}
	c.tried[key] = i
	c.values[key] = cands[i]
	c.placeholders[key] = true
	return true
}

func (c *stackConfig) configJSON() string {
	b, _ := json.Marshal(c.values) // map keys are sorted
	return string(b)
}

func (c *stackConfig) secretKeysJSON() string {
	b, _ := json.Marshal(sortedKeys(c.secrets))
	return string(b)
}

// publicValues are the values that are not secret, for the capture document.
func (c *stackConfig) publicValues() map[string]string {
	out := map[string]string{}
	for k, v := range c.values {
		if !c.secrets[k] {
			out[k] = v
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func qualify(key, project string) string {
	if strings.Contains(key, ":") {
		return key
	}
	return project + ":" + key
}

// encodeConfig encodes a value as Pulumi passes configuration to programs:
// strings as is, structured values as JSON.
func encodeConfig(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return valueTrue
		}
		return valueFalse
	case nil:
		return ""
	case map[string]any, []any:
		b, err := json.Marshal(t)
		if err != nil {
			return ""
		}
		return string(b)
	}
	return fmt.Sprint(v)
}

var (
	pathLike   = regexp.MustCompile(`path|dir|folder`)
	domainLike = regexp.MustCompile(`domain|host|fqdn|dns`)
)

// candidatesFor lists the values to try for a missing key, best first: typed
// from the accessor the program uses (require_int, RequireObject...), then
// from the key name.
func candidatesFor(key string, src *sourceIndex) []string {
	short := strings.ToLower(key[strings.LastIndex(key, ":")+1:])
	var first []string
	switch src.accessorType(key) {
	case typeObject:
		first = []string{"[]", "{}"}
		if strings.Contains(short, "cidr") {
			first = []string{`["10.0.0.0/24","10.0.1.0/24","10.0.2.0/24"]`, "[]", "{}"}
		}
	case "int":
		first = []string{"1"}
	case typeFloat:
		first = []string{"1.5"}
	case "bool":
		first = []string{valueFalse}
	default:
		switch {
		case pathLike.MatchString(short):
			first = []string{"."}
		case strings.Contains(short, "cidr"):
			first = []string{"10.0.0.0/16"}
		case strings.Contains(short, "region"):
			first = []string{schemagen.Region["aws"]}
		case domainLike.MatchString(short):
			first = []string{schemagen.Text + ".example.com"}
		default:
			// Short lowercase alphanumeric: survives the name-length and
			// charset checks programs often make.
			first = []string{"ddph"}
		}
	}
	out := append([]string(nil), first...)
	for _, c := range genericCandidates {
		if !contains(out, c) {
			out = append(out, c)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

// sourceIndex finds how a program reads a configuration key.
type sourceIndex struct {
	files map[string]string // path -> content, .py and .go files of the project
}

// skippedDirs are not the user's program.
var skippedDirs = map[string]bool{
	"venv": true, ".venv": true, "vendor": true, "site-packages": true, "node_modules": true, ".git": true, "__pycache__": true,
}

// maxIndexedFiles and maxIndexedBytes bound the source index.
const (
	maxIndexedFiles = 2000
	maxIndexedBytes = 1 << 20
)

func newSourceIndex(dir string) *sourceIndex {
	idx := &sourceIndex{files: map[string]string{}}
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != dir && skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".py" && ext != ".go" || len(idx.files) >= maxIndexedFiles {
			return nil
		}
		// Only regular files: a symbolic link could point to a device or to a
		// large file outside the project.
		if d.Type()&fs.ModeType != 0 {
			return nil
		}
		if info, err := d.Info(); err != nil || info.Size() > maxIndexedBytes {
			return nil
		}
		if b, ok := readIndexedFile(path); ok {
			idx.files[path] = string(b)
		}
		return nil
	})
	return idx
}

// readIndexedFile reads at most maxIndexedBytes, in case the file grew since
// it was listed; a larger file is not indexed.
func readIndexedFile(path string) ([]byte, bool) {
	f, err := os.Open(path) //nolint:gosec // a source file of the project
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxIndexedBytes+1))
	if err != nil || len(b) > maxIndexedBytes {
		return nil, false
	}
	return b, true
}

const (
	accessorPython = `\.(?:require|get)(?:_secret)?(_object|_int|_bool|_float)?\(\s*['"]%s['"]`
	accessorGo     = `(?:Require|Get|Try)(?:Secret)?(Object|Int|Bool|Float64)?\(\s*(?:ctx\s*,\s*)?"%s"`
)

// accessorType returns object, int, float, bool or string for the accessor a
// program uses to read key, or "" when the key is not found in the sources.
func (s *sourceIndex) accessorType(key string) string {
	if s == nil {
		return ""
	}
	short := regexp.QuoteMeta(key[strings.LastIndex(key, ":")+1:])
	py := regexp.MustCompile(fmt.Sprintf(accessorPython, short))
	golang := regexp.MustCompile(fmt.Sprintf(accessorGo, short))
	paths := make([]string, 0, len(s.files))
	for p := range s.files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		re := py
		if strings.HasSuffix(p, ".go") {
			re = golang
		}
		if m := re.FindStringSubmatch(s.files[p]); m != nil {
			t := strings.TrimPrefix(strings.ToLower(m[1]), "_")
			switch t {
			case "":
				return "string"
			case "float64":
				return typeFloat
			default:
				return t
			}
		}
	}
	return ""
}
