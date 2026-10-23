package file

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-iac-scanner/test"
	"gopkg.in/yaml.v3"
)

func TestResolver_Resolve_With_ResolveReferences(t *testing.T) {
	err := test.ChangeCurrentDir("datadog-iac-scanner")
	if err != nil {
		t.Fatal(err)
	}
	type fields struct {
		*Resolver
	}
	type args struct {
		path string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []byte
	}{
		{
			name: "test",
			fields: fields{
				Resolver: NewResolver(yaml.Unmarshal, yaml.Marshal, []string{".yml", ".yaml"}),
			},
			args: args{
				path: filepath.ToSlash("test/fixtures/unresolved_openapi/responses/_index.yaml"),
			},
			want: []byte(
				`UnexpectedError:description:unexpectederrorcontent:application/json:schema:type:objectrequired:-code-messageproperties:code:type:integerformat:int32message:type:stringRefMetadata:$ref:"../schemas/Error.yaml"alone:trueRefMetadata:$ref:"./UnexpectedError.yaml"alone:trueNullResponse:description:NullresponseRefMetadata:$ref:"./NullResponse.yaml"alone:true`),
		},
		{
			name: "json test",
			fields: fields{
				Resolver: NewResolver(json.Unmarshal, json.Marshal, []string{".json"}),
			},
			args: args{
				path: filepath.ToSlash("test/fixtures/unresolved_openapi_json/openapi.json"),
			},
			want: []byte(
				"{\"info\":{\"title\":\"Reference in reference example\",\"version\":\"1.0.0\"},\"openapi\":\"3.0.3\",\"paths\":{\"/api/test/ref/in/ref\":{\"post\":{\"requestBody\":{\"content\":{\"application/json\":{\"schema\":{\"RefMetadata\":{\"$ref\":\"messages/request.json\",\"alone\":true},\"properties\":{\"definition_reference\":{\"RefMetadata\":{\"$ref\":\"definitions.json#/definitions/External\",\"alone\":true},\"type\":\"string\"}},\"required\":[\"definition_reference\"],\"type\":\"object\"}}}},\"responses\":{\"200\":{\"content\":{\"application/json\":{\"schema\":{\"RefMetadata\":{\"$ref\":\"messages/response.json\",\"alone\":true},\"properties\":{\"id\":{\"format\":\"int32\",\"type\":\"integer\"}},\"type\":\"object\"}}},\"description\":\"Successful response\"}}}}}}",
			),
		},
		{
			name: "test_serverless",
			fields: fields{
				Resolver: NewResolver(yaml.Unmarshal, yaml.Marshal, []string{".yml", ".yaml"}),
			},
			args: args{
				path: filepath.ToSlash("test/fixtures/unresolved_serverless/serverless.yml"),
			},
			want: []byte(
				"service: aws-node-project\nframeworkVersion: '3'\nprovider:\n    name: aws\n    runtime: nodejs14.x\nfunctions:\n    eventRouterHandler:\n        handler: handler.hello\n        role: eventRouterHandlerRole\n        timeout: 30\n"),
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Resolver{
				unmarshler:    tt.fields.unmarshler,
				marshler:      tt.fields.marshler,
				ResolvedFiles: tt.fields.ResolvedFiles,
				Extension:     tt.fields.Extension,
			}

			cont, err := getFileContent(tt.args.path)
			if err != nil {
				t.Fatal(err)
			}

			if got := r.Resolve(ctx, cont, tt.args.path, 0, 15, make(map[string]ResolvedFile), true); !reflect.DeepEqual(prepareString(string(got)), prepareString(string(tt.want))) {
				t.Errorf("Resolve() = %v, want = %v", prepareString(string(got)), prepareString(string(tt.want)))
			}
		})
	}
}

func TestResolver_Resolve_Without_ResolveReferences(t *testing.T) {
	err := test.ChangeCurrentDir("datadog-iac-scanner")
	if err != nil {
		t.Fatal(err)
	}
	type fields struct {
		*Resolver
	}
	type args struct {
		path string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []byte
	}{
		{
			name: "yaml should resolve because is not openapi file",
			fields: fields{
				Resolver: NewResolver(yaml.Unmarshal, yaml.Marshal, []string{".yml", ".yaml"}),
			},
			args: args{
				path: filepath.ToSlash("test/fixtures/unresolved_openapi/responses/_index.yaml"),
			},
			want: []byte(
				`UnexpectedError:description:unexpectederrorcontent:application/json:schema:type:objectrequired:-code-messageproperties:code:type:integerformat:int32message:type:stringRefMetadata:$ref:"../schemas/Error.yaml"alone:trueRefMetadata:$ref:"./UnexpectedError.yaml"alone:trueNullResponse:description:NullresponseRefMetadata:$ref:"./NullResponse.yaml"alone:true`),
		},
		{
			name: "json should not resolve because is a openapi file",
			fields: fields{
				Resolver: NewResolver(json.Unmarshal, json.Marshal, []string{".json"}),
			},
			args: args{
				path: filepath.ToSlash("test/fixtures/unresolved_openapi_json/openapi.json"),
			},
			want: []byte(
				"{\"openapi\":\"3.0.3\",\"info\":{\"title\":\"Reference in reference example\",\"version\":\"1.0.0\"},\"paths\":{\"/api/test/ref/in/ref\":{\"post\":{\"requestBody\":{\"content\":{\"application/json\":{\"schema\":{\"$ref\":\"messages/request.json\"}}}},\"responses\":{\"200\":{\"description\":\"Successful response\",\"content\":{\"application/json\":{\"schema\":{\"$ref\":\"messages/response.json\"}}}}}}}}}",
			),
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Resolver{
				unmarshler:    tt.fields.unmarshler,
				marshler:      tt.fields.marshler,
				ResolvedFiles: tt.fields.ResolvedFiles,
				Extension:     tt.fields.Extension,
			}

			cont, err := getFileContent(tt.args.path)
			if err != nil {
				t.Fatal(err)
			}

			if got := r.Resolve(ctx, cont, tt.args.path, 0, 15, make(map[string]ResolvedFile), false); !reflect.DeepEqual(prepareString(string(got)), prepareString(string(tt.want))) {
				t.Errorf("Resolve() = %v, want = %v", prepareString(string(got)), prepareString(string(tt.want)))
			}
		})
	}
}

// when using the key 'include_vars', the resolver will search for the file inside the folder 'current_path/vars' and then in the 'current_path'.
func TestResolver_Resolve_Ansible_Vars(t *testing.T) {
	err := test.ChangeCurrentDir("datadog-iac-scanner")
	if err != nil {
		t.Fatal(err)
	}
	type fields struct {
		*Resolver
	}
	type args struct {
		path string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []byte
	}{
		{
			name: "resolve ansible vars when vars folder is present",
			fields: fields{
				Resolver: NewResolver(yaml.Unmarshal, yaml.Marshal, []string{".yml", ".yaml"}),
			},
			args: args{
				path: filepath.ToSlash("test/fixtures/resolve_ansible_vars_with_vars_folder/main.yml"),
			},
			want: []byte(
				`-hosts:localhosttasks:-name:Includetask.ymlansible.builtin.include_tasks:-name:Addvariablesansible.builtin.include_vars:world:"World"-name:Printvariablefrommain.ymldebug:msg:"Hello{{world}}"-name:Includetask.ymlagainansible.builtin.include_tasks:-name:Addvariablesansible.builtin.include_vars:world:"World"-name:Printvariablefrommain.ymldebug:msg:"Hello{{world}}"`,
			),
		},
		{
			name: "resolve ansible vars when vars folder is not present",
			fields: fields{
				Resolver: NewResolver(yaml.Unmarshal, yaml.Marshal, []string{".yml", ".yaml"}),
			},
			args: args{
				path: filepath.ToSlash("test/fixtures/resolve_ansible_vars_without_vars_folder/main.yml"),
			},
			want: []byte(
				`-hosts:localhosttasks:-name:Includetask.ymlansible.builtin.include_tasks:-name:Addvariablesinclude_vars:world:"World"-name:Printvariablefrommain.ymldebug:msg:"Hello{{world}}"-name:Includetask.ymlagainansible.builtin.include_tasks:-name:Addvariablesinclude_vars:world:"World"-name:Printvariablefrommain.ymldebug:msg:"Hello{{world}}"`,
			),
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Resolver{
				unmarshler:    tt.fields.unmarshler,
				marshler:      tt.fields.marshler,
				ResolvedFiles: tt.fields.ResolvedFiles,
				Extension:     tt.fields.Extension,
			}

			cont, err := getFileContent(tt.args.path)
			if err != nil {
				t.Fatal(err)
			}

			if got := r.Resolve(ctx, cont, tt.args.path, 0, 15, make(map[string]ResolvedFile), false); !reflect.DeepEqual(prepareString(string(got)), prepareString(string(tt.want))) {
				t.Errorf("Resolve() = %v, want = %v", prepareString(string(got)), prepareString(string(tt.want)))
			}
		})
	}
}

func Test_IsOpenApi(t *testing.T) {
	err := test.ChangeCurrentDir("datadog-iac-scanner")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "yaml Open Api",
			path: "test/fixtures/resolve_references/swagger.yaml",
			want: true,
		},
		{
			name: "json Open Api",
			path: "test/fixtures/resolve_references_json/scan-2files.json",
			want: true,
		},
		{
			name: "yml not Open Api",
			path: "test/fixtures/resolve_references/paths/users/user.yaml",
			want: false,
		},
		{
			name: "json not Open Api",
			path: "test/fixtures/resolve_references_json/definitions.json",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cont, err := getFileContent(tt.path)
			require.NoError(t, err)
			got := isOpenAPI(cont)
			assert.Equal(t, tt.want, got, fmt.Sprintf("Error: %s", tt.name))
		})
	}
}

func getFileContent(path string) ([]byte, error) {
	_, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	return ioutil.ReadFile(path)
}

func prepareString(content string) string {
	content = strings.Replace(content, "\n", "", -1)
	content = strings.Replace(content, "\t", "", -1)
	content = strings.Replace(content, "\r", "", -1)
	content = strings.Replace(content, " ", "", -1)
	return content
}

func TestCheckServerlessFileReference(t *testing.T) {
	t.Parallel()
	require.Equal(t, "config/settings.yaml", checkServerlessFileReference("${file(config/settings.yaml)}"))
	require.Equal(t, "plain/path.yml", checkServerlessFileReference("plain/path.yml"))
}

func TestSplitYAMLStream(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{name: "single document", content: "a: 1\nb: 2\n", want: []string{"a: 1\nb: 2\n"}},
		{name: "leading marker", content: "---\na: 1\n", want: []string{"---\na: 1\n"}},
		{name: "content before the first marker", content: "a: 1\n---\nb: 2\n", want: []string{"a: 1\n", "---\nb: 2\n"}},
		{name: "trailing marker", content: "a: 1\n---\n", want: []string{"a: 1\n", "---\n"}},
		{
			name:    "comments, blanks and directives before the first marker",
			content: "# c\n\n%YAML 1.1\n---\na: 1\n---\nb: 2\n",
			want:    []string{"# c\n\n%YAML 1.1\n---\na: 1\n", "---\nb: 2\n"},
		},
		{
			name:    "marker followed by content or a comment",
			content: "--- a: 1\n--- # c\nb: 2\n",
			want:    []string{"--- a: 1\n", "--- # c\nb: 2\n"},
		},
		{
			name:    "byte order mark",
			content: "\uFEFF---\na: 1\n---\nb: 2\n",
			want:    []string{"\uFEFF---\na: 1\n", "---\nb: 2\n"},
		},
		{name: "CRLF line endings", content: "a: 1\r\n---\r\nb: 2\r\n", want: []string{"a: 1\r\n", "---\r\nb: 2\r\n"}},
		{
			name:    "dashes that are not a marker",
			content: "a: |\n  ---\nb: ---\n---c: 1\n",
			want:    []string{"a: |\n  ---\nb: ---\n---c: 1\n"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got []string
			for _, doc := range splitYAMLStream([]byte(tt.content)) {
				got = append(got, string(doc))
			}
			require.Equal(t, tt.want, got)
		})
	}
}

const yamlStreamWithReferences = `apiVersion: v1
kind: ConfigMap
metadata:
  name: first
data:
  path: extra.yaml
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: second
data:
  path: other.yaml
---
apiVersion: v1
kind: Pod
metadata:
  name: priv
`

// writeYamlStreamFixture writes the files the stream references and returns
// the path of the stream itself, which is left unwritten.
func writeYamlStreamFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "extra.yaml"), []byte("foo: bar\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "other.yaml"), []byte("baz: qux\n"), 0o600))
	return filepath.Join(dir, "manifests.yaml")
}

func decodeYamlStream(t *testing.T, content []byte) []map[string]any {
	t.Helper()
	var docs []map[string]any
	dec := yaml.NewDecoder(strings.NewReader(string(content)))
	for {
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			require.ErrorIs(t, err, io.EOF)
			return docs
		}
		docs = append(docs, doc)
	}
}

func TestResolver_Resolve_YamlStream(t *testing.T) {
	ctx := context.Background()
	extensions := []string{".yml", ".yaml"}

	t.Run("resolves every document and keeps them all", func(t *testing.T) {
		path := writeYamlStreamFixture(t)
		r := NewResolver(yaml.Unmarshal, yaml.Marshal, extensions)

		got := r.Resolve(ctx, []byte(yamlStreamWithReferences), path, 0, 15, make(map[string]ResolvedFile), false)

		docs := decodeYamlStream(t, got)
		require.Len(t, docs, 3)
		assert.Equal(t, map[string]any{"path": map[string]any{"foo": "bar"}}, docs[0]["data"])
		assert.Equal(t, map[string]any{"path": map[string]any{"baz": "qux"}}, docs[1]["data"])
		assert.Equal(t, "Pod", docs[2]["kind"])
		assert.True(t, strings.HasSuffix(string(got), "---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: priv\n"),
			"a document without a reference should be kept as written, got:\n%s", got)
		assert.Contains(t, r.ResolvedFiles, "extra.yaml")
		assert.Contains(t, r.ResolvedFiles, "other.yaml")
	})

	t.Run("returns the stream as written when nothing resolves", func(t *testing.T) {
		path := writeYamlStreamFixture(t)
		content := "# header\napiVersion: v1\nkind: ConfigMap\ndata:\n  path: missing.yaml\n---\napiVersion: v1\nkind: Pod\n"
		r := NewResolver(yaml.Unmarshal, func(v any) ([]byte, error) {
			t.Error("re-encoded a stream that resolved no reference")
			return yaml.Marshal(v)
		}, extensions)

		got := r.Resolve(ctx, []byte(content), path, 0, 15, make(map[string]ResolvedFile), false)

		assert.Equal(t, content, string(got))
		assert.Empty(t, r.ResolvedFiles)
	})

	t.Run("keeps an undecodable document as written and resolves the others", func(t *testing.T) {
		path := writeYamlStreamFixture(t)
		broken := "---\nkind: Pod\nspec: [unterminated, other.yaml\n"
		content := "kind: ConfigMap\ndata:\n  path: extra.yaml\n" + broken + "---\nkind: Secret\ndata:\n  path: other.yaml\n"
		r := NewResolver(yaml.Unmarshal, yaml.Marshal, extensions)

		got := r.Resolve(ctx, []byte(content), path, 0, 15, make(map[string]ResolvedFile), false)

		assert.Equal(t,
			"kind: ConfigMap\ndata:\n    path:\n        foo: bar\n"+broken+"---\nkind: Secret\ndata:\n    path:\n        baz: qux\n",
			string(got))
		assert.Contains(t, r.ResolvedFiles, "extra.yaml")
		assert.Contains(t, r.ResolvedFiles, "other.yaml")
	})

	t.Run("decodes through the injected unmarshaler", func(t *testing.T) {
		path := writeYamlStreamFixture(t)
		r := NewResolver(func([]byte, any) error { return errors.New("injected") }, yaml.Marshal, extensions)

		got := r.Resolve(ctx, []byte(yamlStreamWithReferences), path, 0, 15, make(map[string]ResolvedFile), false)

		assert.Equal(t, yamlStreamWithReferences, string(got))
		assert.Empty(t, r.ResolvedFiles)
	})

	t.Run("encodes through the injected marshaler", func(t *testing.T) {
		path := writeYamlStreamFixture(t)
		r := NewResolver(yaml.Unmarshal, func(any) ([]byte, error) { return nil, errors.New("injected") }, extensions)

		got := r.Resolve(ctx, []byte(yamlStreamWithReferences), path, 0, 15, make(map[string]ResolvedFile), false)

		assert.Equal(t, yamlStreamWithReferences, string(got))
	})
}
