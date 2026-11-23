package file

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
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
				Resolver: NewResolver(nil, yaml.Unmarshal, yaml.Marshal, []string{".yml", ".yaml"}),
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
				Resolver: NewResolver(nil, json.Unmarshal, json.Marshal, []string{".json"}),
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
				Resolver: NewResolver(nil, yaml.Unmarshal, yaml.Marshal, []string{".yml", ".yaml"}),
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
				fsys:          tt.fields.fsys,
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
				Resolver: NewResolver(nil, yaml.Unmarshal, yaml.Marshal, []string{".yml", ".yaml"}),
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
				Resolver: NewResolver(nil, json.Unmarshal, json.Marshal, []string{".json"}),
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
				fsys:          tt.fields.fsys,
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
				Resolver: NewResolver(nil, yaml.Unmarshal, yaml.Marshal, []string{".yml", ".yaml"}),
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
				Resolver: NewResolver(nil, yaml.Unmarshal, yaml.Marshal, []string{".yml", ".yaml"}),
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
				fsys:          tt.fields.fsys,
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

// mappingValue returns the value of key in a YAML mapping node.
func mappingValue(t *testing.T, mapping *yaml.Node, key string) *yaml.Node {
	t.Helper()
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	t.Fatalf("no key %q", key)
	return nil
}

// Every reference to a file points at the same resolved nodes, keeps its own
// reference metadata, and has no position in the referencing file.
func TestResolver_ResolveYAML_SharesReferencedFile(t *testing.T) {
	dir := t.TempDir()
	schema := "type: object\nrequired:\n  - id\nproperties:\n  id:\n    type: integer\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "schema.yaml"), []byte(schema), 0o600))
	path := filepath.Join(dir, "main.yaml")
	content := []byte("a:\n  $ref: ./schema.yaml\nb:\n  $ref: ./schema.yaml\n  description: second\n")

	r := NewResolver(nil, yaml.Unmarshal, yaml.Marshal, []string{".yml", ".yaml"})
	docs := r.ResolveYAML(context.Background(), content, path, 15, true)

	require.Len(t, docs, 1)
	require.Contains(t, r.ResolvedFiles, "./schema.yaml")
	root := docs[0].Content[0]
	a, b := mappingValue(t, root, "a"), mappingValue(t, root, "b")
	require.Same(t, mappingValue(t, a, "properties"), mappingValue(t, b, "properties"))
	require.Equal(t, "true", mappingValue(t, mappingValue(t, a, "RefMetadata"), "alone").Value)
	require.Equal(t, "false", mappingValue(t, mappingValue(t, b, "RefMetadata"), "alone").Value)
	require.Equal(t, 1, root.Content[0].Line)
	require.Zero(t, mappingValue(t, a, "properties").Line)
}

func TestResolver_ReferenceFilesystemIdentity(t *testing.T) {
	for _, format := range []string{"yaml", "json"} {
		t.Run(format, func(t *testing.T) {
			extension := "." + format
			schema := "schema" + extension
			for _, feature := range []struct {
				name, source string
				assets       map[string][]byte
				reads        int
				want         string
				readFailure  bool
				wantRef      bool
			}{
				{"file fragment", `{"v":{"$ref":"` + schema + `#/definition"}}`, map[string][]byte{"dir/" + schema: []byte(`{"definition":{"marker":"owned"}}`)}, 1, "owned", false, false},
				{"fragment key contains hash", `{"v":{"$ref":"` + schema + `#/de#finition"}}`, map[string][]byte{"dir/" + schema: []byte(`{"de#finition":{"marker":"owned"}}`)}, 1, "owned", false, false},
				{"fragment does not change file type", `{"v":{"$ref":"` + schema + `#/definition.txt"}}`, map[string][]byte{"dir/" + schema: []byte(`{"definition.txt":{"marker":"owned"}}`)}, 1, "owned", false, false},
				{"empty fragment selects root", `{"v":{"$ref":"` + schema + `#"}}`, map[string][]byte{"dir/" + schema: []byte(`{"marker":"owned"}`)}, 1, "owned", false, false},
				{"unsupported named fragment", `{"v":{"$ref":"` + schema + `#definition"}}`, map[string][]byte{"dir/" + schema: []byte(`{"efinition":{"marker":"must-not-resolve"}}`)}, 1, "", false, false},

				{"missing fragment matches last mapping value", `{"v":{"$ref":"` + schema + `#/target"},"independent":"other` + extension + `"}`, map[string][]byte{
					"dir/" + schema: []byte(`{"key":"target"}`), "dir/other" + extension: []byte(`{"marker":"independent"}`),
				}, 2, "", false, true},
				{"missing fragment matches another mapping value", `{"v":{"$ref":"` + schema + `#/target"},"independent":"other` + extension + `"}`, map[string][]byte{
					"dir/" + schema:         []byte(`{"key":"target","after":{"marker":"wrong"}}`),
					"dir/other" + extension: []byte(`{"marker":"independent"}`),
				}, 2, "", false, true},
				{"fragment cannot traverse scalar", `{"v":{"$ref":"` + schema + `#/target/tail"},"independent":"other` + extension + `"}`, map[string][]byte{
					"dir/" + schema: []byte(`{"target":"tail"}`), "dir/other" + extension: []byte(`{"marker":"independent"}`),
				}, 2, "", false, true},
				{"fragment cannot select sequence value", `{"v":{"$ref":"` + schema + `#/target/tail"},"independent":"other` + extension + `"}`, map[string][]byte{
					"dir/" + schema: []byte(`{"target":["tail"]}`), "dir/other" + extension: []byte(`{"marker":"independent"}`),
				}, 2, "", false, true},
				{"canonical aliases", `{"a":"` + schema + `","b":"./` + schema + `","c":"sub/../` + schema + `"}`, map[string][]byte{"dir/" + schema: []byte(`{"marker":"owned"}`)}, 1, "owned", false, false},
				{"fragment does not select file type", `{"v":"x/#y` + extension + `"}`, map[string][]byte{
					"dir/x":                []byte(`{"a":"../x/#y` + extension + `","b":"../x/#y` + extension + `","c":"../x/#y` + extension + `"}`),
					"dir/x/#y" + extension: []byte(`{"marker":"wrong file"}`),
				}, 0, "", false, false},
				{"cycle aliases", `{"v":"` + schema + `"}`, map[string][]byte{"dir/" + schema: []byte(`{"a":"./` + schema + `","b":"sub/../` + schema + `","c":"./` + schema + `"}`)}, 1, "", false, false},
				{"empty file", `{"a":"` + schema + `","b":"./` + schema + `","c":"sub/../` + schema + `"}`, map[string][]byte{"dir/" + schema: nil}, 1, "", false, false},
				{"unreadable file", `{"a":"` + schema + `","b":"./` + schema + `","c":"sub/../` + schema + `"}`, map[string][]byte{"dir/" + schema: []byte(`{"marker":"owned"}`)}, 1, "", true, false},
			} {
				t.Run(feature.name, func(t *testing.T) {
					fsys := &referenceReadFS{FS: vfs.NewMemFS(feature.assets), reads: map[string]int{}}
					if feature.readFailure {
						fsys.failPath = "dir/" + schema
					}
					r := NewResolver(fsys, json.Unmarshal, json.Marshal, []string{extension})
					source := []byte(feature.source)
					var encoded []byte
					if format == "yaml" {
						r = NewResolver(fsys, yaml.Unmarshal, yaml.Marshal, []string{extension})
						docs := r.ResolveYAML(t.Context(), source, "dir/main"+extension, 6, true)
						require.Len(t, docs, 1)
						var document map[string]any
						require.NoError(t, docs[0].Decode(&document))
						var err error
						encoded, err = json.Marshal(document)
						require.NoError(t, err)
					} else {
						encoded = r.Resolve(t.Context(), source, "dir/main"+extension, 0, 6, map[string]ResolvedFile{}, true)
					}
					require.Equal(t, feature.reads, fsys.totalReads(), "each file identity is read at most once, including cycles")
					require.NotContains(t, string(encoded), "must-not-resolve", "unsupported fragments must not select a similarly named key")
					if feature.wantRef {
						var sourceDocument, document map[string]any
						require.NoError(t, json.Unmarshal(source, &sourceDocument))
						require.NoError(t, json.Unmarshal(encoded, &document))
						reference, ok := document["v"].(map[string]any)
						require.True(t, ok)
						if metadata, ok := reference["RefMetadata"].(map[string]any); ok {
							reference = metadata
						}
						require.Equal(t, sourceDocument["v"].(map[string]any)["$ref"], reference["$ref"],
							"an unsupported or missing fragment preserves the reference identity")
						independent, ok := document["independent"].(map[string]any)
						require.True(t, ok, "a missing fragment must not discard independent references")
						require.Equal(t, "independent", independent["marker"])
					}

					if feature.want != "" {
						var document map[string]any
						require.NoError(t, json.Unmarshal(encoded, &document))
						key := "a"
						if _, exists := document["v"]; exists {
							key = "v"
						}
						target, ok := document[key].(map[string]any)
						require.True(t, ok)
						require.Equal(t, feature.want, target["marker"])
						require.NotContains(t, target, "definition", "the fragment selects a section, not the complete file")
					}
					for path := range fsys.reads {
						require.Equal(t, filepath.Clean(path), path)
					}
				})
			}
		})
	}
}

func TestResolver_ReferenceCancellation(t *testing.T) {
	for _, format := range []string{"yaml", "json"} {
		for _, phase := range []string{"before resolution", "after first read"} {
			t.Run(format+"/"+phase, func(t *testing.T) {
				extension := "." + format
				source := []byte(`{"v":"schema` + extension + `"}`)
				assets := map[string][]byte{
					"dir/schema" + extension: []byte(`{"v":"leaf` + extension + `"}`),
					"dir/leaf" + extension:   []byte(`{"marker":"owned"}`),
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				fsys := &referenceReadFS{FS: vfs.NewMemFS(assets), reads: map[string]int{}}
				wantReads := 0
				if phase == "before resolution" {
					cancel()
				} else {
					fsys.afterRead = cancel
					wantReads = 1
				}
				r := NewResolver(fsys, json.Unmarshal, json.Marshal, []string{extension})
				if format == "yaml" {
					r = NewResolver(fsys, yaml.Unmarshal, yaml.Marshal, []string{extension})
					require.Empty(t, r.ResolveYAML(ctx, source, "dir/main"+extension, 6, true))
				} else {
					require.Equal(t, source, r.Resolve(ctx, source, "dir/main"+extension, 0, 6, map[string]ResolvedFile{}, true))
				}
				require.ErrorIs(t, ctx.Err(), context.Canceled)
				require.Equal(t, wantReads, fsys.totalReads())
				require.Empty(t, r.ResolvedFiles, "canceled resolution must not publish partial references")
			})
		}
	}
}

type referenceReadFS struct {
	vfs.FS
	reads     map[string]int
	afterRead func()
	failPath  string
}

func (f *referenceReadFS) ReadFile(path string) ([]byte, error) {
	f.reads[path]++
	if path == f.failPath {
		return nil, os.ErrPermission
	}
	content, err := f.FS.ReadFile(path)
	if f.afterRead != nil {
		f.afterRead()
	}
	return content, err
}

func (f *referenceReadFS) totalReads() int {
	total := 0
	for _, reads := range f.reads {
		total += reads
	}
	return total
}

func TestResolver_ReferenceResolutionContexts(t *testing.T) {
	for _, format := range []string{"yaml", "json"} {
		t.Run(format, func(t *testing.T) {
			extension := "." + format
			resolve := func(t *testing.T, source string, assets map[string][]byte, depth int) (map[string]any, int, int) {
				t.Helper()
				fsys := &referenceReadFS{FS: vfs.NewMemFS(assets), reads: map[string]int{}}
				decodes := 0
				unmarshal := json.Unmarshal
				if format == "yaml" {
					unmarshal = yaml.Unmarshal
				}
				r := NewResolver(fsys, func(content []byte, value any) error { decodes++; return unmarshal(content, value) }, json.Marshal, []string{extension})
				var document map[string]any
				if format == "yaml" {
					docs := r.ResolveYAML(t.Context(), []byte(source), "dir/main"+extension, depth, true)
					require.Len(t, docs, 1)
					require.NoError(t, docs[0].Decode(&document))
				} else {
					output := r.Resolve(t.Context(), []byte(source), "dir/main"+extension, 0, depth, nil, true)
					require.NoError(t, json.Unmarshal(output, &document))
				}
				return document, fsys.totalReads(), decodes
			}
			t.Run("depth diamond", func(t *testing.T) {
				source := `{"deep":"a` + extension + `","direct":"b` + extension + `"}`
				assets := map[string][]byte{
					"dir/a" + extension: []byte(`{"next":"b` + extension + `"}`),
					"dir/b" + extension: []byte(`{"next":"c` + extension + `"}`),
					"dir/c" + extension: []byte(`{"marker":"owned"}`),
				}
				document, reads, _ := resolve(t, source, assets, 2)
				require.Equal(t, 3, reads)
				deep := document["deep"].(map[string]any)["next"].(map[string]any)
				require.Equal(t, "c"+extension, deep["next"], "a shallow memo must not expand a deeper caller beyond its existing frontier")
				direct := document["direct"].(map[string]any)["next"].(map[string]any)
				require.Equal(t, "owned", direct["marker"], "a deep first visit must not truncate a later shallow caller")
			})
			t.Run("branching cycle", func(t *testing.T) {
				assets := map[string][]byte{}
				for i := range 6 {
					current := fmt.Sprintf("dir/n%d%s", i, extension)
					next := fmt.Sprintf("n%d%s", (i+1)%6, extension)
					assets[current] = []byte(fmt.Sprintf(`{"a":%q,"b":%q,"c":%q}`, next, "./"+next, "sub/../"+next))
				}
				_, reads, decodes := resolve(t, `{"v":"n0`+extension+`"}`, assets, 8)
				require.Equal(t, len(assets), reads)
				require.LessOrEqual(t, decodes, 2*len(assets)*8+1, "memoize work by file and existing remaining depth, not by every path through the cycle")
			})
			t.Run("provided root bytes", func(t *testing.T) {
				document, reads, _ := resolve(t, `{"marker":"provided","next":"./main`+extension+`"}`, map[string][]byte{"dir/main" + extension: []byte(`{"marker":"wrong host"}`)}, 3)
				require.Zero(t, reads, "the operation already owns the root bytes")
				require.Equal(t, "provided", document["marker"])
				encoded, err := json.Marshal(document)
				require.NoError(t, err)
				require.NotContains(t, string(encoded), "wrong host")
			})
		})
	}
}

func TestResolver_ReferenceMetadataOwnership(t *testing.T) {
	for _, format := range []string{"yaml", "json"} {
		for _, fragment := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/fragment=%t", format, fragment), func(t *testing.T) {
				extension := "." + format
				schema := "schema" + extension
				content := []byte(`{"marker":"owned","nested":{"value":"shared"}}`)
				suffix := ""
				if fragment {
					content = []byte(`{"definition":{"marker":"owned","nested":{"value":"shared"}}}`)
					suffix = "#/definition"
				}
				first, second := schema+suffix, "./"+schema+suffix
				source := []byte(fmt.Sprintf(`{"a":{"$ref":%q},"b":{"$ref":%q,"description":"sibling"}}`, first, second))
				fsys := &referenceReadFS{FS: vfs.NewMemFS(map[string][]byte{"dir/" + schema: content}), reads: map[string]int{}}
				r := NewResolver(fsys, json.Unmarshal, json.Marshal, []string{extension})
				var document map[string]any
				if format == "yaml" {
					r = NewResolver(fsys, yaml.Unmarshal, yaml.Marshal, []string{extension})
					docs := r.ResolveYAML(t.Context(), source, "dir/main"+extension, 6, true)
					require.Len(t, docs, 1)
					require.NoError(t, docs[0].Decode(&document))
				} else {
					cache := map[string]ResolvedFile{}
					output := r.Resolve(t.Context(), source, "dir/main"+extension, 0, 6, cache, true)
					require.NoError(t, json.Unmarshal(output, &document))
					cached := cache[filepath.Join("dir", schema)].views[6].(map[string]any)
					if fragment {
						cached = cached["definition"].(map[string]any)
					}
					require.NotContains(t, cached, "RefMetadata", "per-reference metadata must not mutate a cached view")
				}
				for name, want := range map[string]struct {
					reference string
					alone     bool
				}{"a": {first, true}, "b": {second, false}} {
					value := document[name].(map[string]any)
					require.Equal(t, "owned", value["marker"])
					metadata := value["RefMetadata"].(map[string]any)
					require.Equal(t, want.reference, metadata["$ref"])
					require.Equal(t, fmt.Sprint(want.alone), fmt.Sprint(metadata["alone"]))
				}
				require.Equal(t, 1, fsys.totalReads())
			})
		}
	}
}

type precheckFS struct {
	vfs.FS
	stats  int
	cancel context.CancelFunc
}

func (f *precheckFS) Stat(name string) (fs.FileInfo, error) {
	f.stats++
	if f.cancel != nil {
		f.cancel()
	}
	return f.FS.Stat(name)
}

func TestMayResolveRejectsInvalidAndExcessivelyNestedJSON(t *testing.T) {
	for name, content := range map[string]string{
		"excessive arrays":          strings.Repeat("[", 30000) + "0" + strings.Repeat("]", 30000),
		"excessive objects":         strings.Repeat(`{"x":`, 12000) + "0" + strings.Repeat("}", 12000),
		"invalid after candidate":   `{"x":"file.json"} garbage`,
		"truncated after candidate": `{"x":"file.json",`,
	} {
		t.Run(name, func(t *testing.T) {
			files := &precheckFS{FS: vfs.NewMemFS(map[string][]byte{filepath.FromSlash("/scan/file.json"): []byte("{}")})}
			resolver := NewResolver(files, json.Unmarshal, json.Marshal, []string{".json"})
			require.False(t, resolver.MayResolve(context.Background(), []byte(content), "/scan/plan.json"))
			require.Zero(t, files.stats, "invalid input must not reach filesystem resolution")
		})
	}
}

func TestMayResolveHonorsCancellation(t *testing.T) {
	for _, canceled := range []bool{true, false} {
		t.Run(fmt.Sprint(canceled), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			files := &precheckFS{FS: vfs.NewMemFS(nil), cancel: cancel}
			resolver := NewResolver(files, json.Unmarshal, json.Marshal, []string{".json"})
			if canceled {
				cancel()
			}
			content := []byte(`["missing.json","another.json"]`)
			require.False(t, resolver.MayResolve(ctx, content, "/scan/plan.json"))
			if canceled {
				require.Zero(t, files.stats)
			} else {
				require.Equal(t, 1, files.stats)
			}
		})
	}
}

// The oracle walks encoding/json's decoded values, independently of the token
// state machine. Keep cases where ref status crosses arrays but resets at maps.
func FuzzMayResolveDoesNotMissReferences(f *testing.F) {
	for _, seed := range []string{
		`{"$ref":"#/definition","$ref":null}`,
		`{"x":"file.json","x":null}`,
		`{"x":"file.json"}`,
		`{"x":"file\u002ejson"}`,
		`{"$ref":[["#/definition"]]}`,
		`{"$ref":{"x":"#/definition"}}`,
		`{"x":[{"$ref":"#/definition"}]}`,
		`{"$ref":"#","next":["#/definition"]}`,
		`{"x":{"ref":"#/definition"},"y":{"allOf$REF":["#/definition"]}}`,
		`{"x":1e999,"y":null,"z":true}`,
		`{"x":"plan.json","file.json":"unrelated"}`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 65536 {
			t.Skip()
		}
		var decoded any
		if json.Unmarshal([]byte(input), &decoded) != nil {
			return
		}
		files := vfs.NewMemFS(map[string][]byte{filepath.FromSlash("/scan/file.json"): []byte("{}")})
		resolver := NewResolver(files, json.Unmarshal, json.Marshal, []string{".json"})
		var walk func(any, bool) bool
		walk = func(value any, ref bool) bool {
			switch value := value.(type) {
			case string:
				if value == "plan.json" {
					return false
				}
				if strings.HasPrefix(value, "#") {
					return ref && value != "#"
				}
				exists, _, _ := resolver.findFilePath(filepath.FromSlash("/scan"), value, false, []string{".json"})
				return exists
			case []any:
				for _, child := range value {
					if walk(child, ref) {
						return true
					}
				}
			case map[string]any:
				for key, child := range value {
					if walk(child, strings.Contains(strings.ToLower(key), "$ref")) {
						return true
					}
				}
			}
			return false
		}
		// A precheck may conservatively report a candidate overwritten by a
		// later duplicate key. It must never skip a reference in the decoded
		// document; exact eligibility for common cases is tested separately.
		got := resolver.MayResolve(context.Background(), []byte(input), "/scan/plan.json")
		if walk(decoded, false) {
			require.True(t, got)
		}
	})
}

func BenchmarkMayResolveNestedJSON(b *testing.B) {
	resolver := NewResolver(vfs.NewMemFS(nil), json.Unmarshal, json.Marshal, []string{".json"})
	for _, depth := range []int{1000, 8000, 30000} {
		content := []byte(strings.Repeat("[", depth) + "0" + strings.Repeat("]", depth))
		b.Run(fmt.Sprint(depth), func(b *testing.B) {
			b.SetBytes(int64(len(content)))
			b.ReportAllocs()
			for b.Loop() {
				if resolver.MayResolve(context.Background(), content, "/scan/plan.json") {
					b.Fatal("unexpected reference")
				}
			}
		})
	}
}
