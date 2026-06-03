/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package buildah

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestParser_Parse tests the parsing of a Buildah file.
func TestParser_Parse(t *testing.T) {
	type args struct {
		in0         string
		fileContent []byte
	}
	tests := []struct {
		name    string
		p       *Parser
		args    args
		want    string
		want1   []int
		wantErr bool
	}{
		{
			name: "Buildah simple parse",
			p:    &Parser{},
			args: args{
				in0: "test.sh",
				fileContent: []byte(`
				ctr=$(buildah from fedora)
				buildah config --env GOPATH=/root/buildah $ctr
				`),
			},
			want: `[
				{
					"command": {
						"fedora": [
							{
								"Cmd": "buildah from",
								"EndLine": 2,
								"Original": "buildah from fedora",
								"Value": "fedora",
								"_dd_line": 2,
						"_kics_line": 2
							},
							{
								"Cmd": "buildah config",
								"EndLine": 3,
								"Original": "buildah config --env GOPATH=/root/buildah $ctr",
								"Value": "--env GOPATH=/root/buildah $ctr",
								"_dd_line": 3,
						"_kics_line": 3
							}
						]
					}
				}
			]`,
			want1:   []int(nil),
			wantErr: false,
		}, {
			name: "Buildah with normal comments parse",
			p:    &Parser{},
			args: args{
				in0: "test.sh",
				fileContent: []byte(`#
				ctr=$(buildah from fedora)
				# buildah config --env GOPATH=/root/buildah $ctr
				buildah commit $ctr buildahupstream
				# buildah run "$ctr" mkdir /tmp/open
				`),
			},
			want: `[
				{
					"command": {
						"fedora": [
							{
								"Cmd": "buildah from",
								"EndLine": 2,
								"Original": "buildah from fedora",
								"Value": "fedora",
								"_dd_line": 2,
						"_kics_line": 2
							},
							{
								"Cmd": "buildah commit",
								"EndLine": 4,
								"Original": "buildah commit $ctr buildahupstream",
								"Value": "$ctr buildahupstream",
								"_dd_line": 4,
						"_kics_line": 4
							}
						]
					}
				}
			]`,
			want1:   []int{1, 3, 5},
			wantErr: false,
		},
		{
			name: "Buildah with normal comments + dd-iac-scan ignore-line parse",
			p:    &Parser{},
			args: args{
				in0: "test.sh",
				fileContent: []byte(`#
				ctr=$(buildah from fedora)
				# dd-iac-scan ignore-line
				buildah config --env GOPATH=/root/buildah $ctr
				buildah commit $ctr buildahupstream
				# buildah run "$ctr" mkdir /tmp/open
				`),
			},
			want: `[
				{
					"command": {
						"fedora": [
							{
								"Cmd": "buildah from",
								"EndLine": 2,
								"Original": "buildah from fedora",
								"Value": "fedora",
								"_dd_line": 2,
						"_kics_line": 2
							},
							{
								"Cmd": "buildah config",
								"EndLine": 4,
								"Original": "buildah config --env GOPATH=/root/buildah $ctr",
								"Value": "--env GOPATH=/root/buildah $ctr",
								"_dd_line": 4,
						"_kics_line": 4
							},
							{
								"Cmd": "buildah commit",
								"EndLine": 5,
								"Original": "buildah commit $ctr buildahupstream",
								"Value": "$ctr buildahupstream",
								"_dd_line": 5,
						"_kics_line": 5
							}
						]
					}
				}
			]`,
			want1:   []int{1, 3, 4, 6},
			wantErr: false,
		},
		{
			name: "Buildah with dd-iac-scan ignore-block related to from parse",
			p:    &Parser{},
			args: args{
				in0: "test.sh",
				fileContent: []byte(`#
				# dd-iac-scan ignore-block
				ctr=$(buildah from fedora)
				buildah run ${ctr} git clone https://github.com/DataDog/datadog-iac-scanner.git
				ctr2=$(buildah from fedora2)
				buildah run ${ctr2} git clone https://github.com/DataDog/datadog-iac-scanner.git
				`),
			},
			want: `[
				{
					"command": {
						"fedora": [
							{
								"Cmd": "buildah from",
								"EndLine": 3,
								"Original": "buildah from fedora",
								"Value": "fedora",
								"_dd_line": 3,
						"_kics_line": 3
							},
							{
								"Cmd": "buildah run",
								"EndLine": 4,
								"Original": "buildah run ${ctr} git clone https://github.com/DataDog/datadog-iac-scanner.git",
								"Value": "${ctr} git clone https://github.com/DataDog/datadog-iac-scanner.git",
								"_dd_line": 4,
						"_kics_line": 4
							}
						],
						"fedora2": [
							{
								"Cmd": "buildah from",
								"EndLine": 5,
								"Original": "buildah from fedora2",
								"Value": "fedora2",
								"_dd_line": 5,
						"_kics_line": 5
							},
							{
								"Cmd": "buildah run",
								"EndLine": 6,
								"Original": "buildah run ${ctr2} git clone https://github.com/DataDog/datadog-iac-scanner.git",
								"Value": "${ctr2} git clone https://github.com/DataDog/datadog-iac-scanner.git",
								"_dd_line": 6,
						"_kics_line": 6
							}
						]
					}
				}
			]`,
			want1:   []int{1, 2, 3, 4},
			wantErr: false,
		}, {
			name: "Buildah with dd-iac-scan ignore-block related to command parse",
			p:    &Parser{},
			args: args{
				in0: "test.sh",
				fileContent: []byte(`#
				ctr=$(buildah from fedora)
				# dd-iac-scan ignore-block
				buildah run $ctr /bin/sh -c 'git clone https://github.com/DataDog/datadog-iac-scanner.git; \
								make'
				`),
			},
			want: `[
				{
					"command": {
						"fedora": [
							{
								"Cmd": "buildah from",
								"EndLine": 2,
								"Original": "buildah from fedora",
								"Value": "fedora",
								"_dd_line": 2,
						"_kics_line": 2
							},
							{
								"Cmd": "buildah run",
								"EndLine": 5,
								"Original": "buildah run $ctr /bin/sh -c 'git clone https://github.com/DataDog/datadog-iac-scanner.git; make'",
								"Value": "$ctr /bin/sh -c 'git clone https://github.com/DataDog/datadog-iac-scanner.git; make'",
								"_dd_line": 4,
						"_kics_line": 4
							}
						]
					}
				}
			]`,
			want1:   []int{1, 3, 4, 5},
			wantErr: false,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Parser{}
			_, got, got1, _, err := p.Parse(ctx, tt.args.fileContent, tt.args.in0, true, 15)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parser.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			gotString, err := json.Marshal(got)
			require.NoError(t, err)
			require.JSONEq(t, tt.want, string(gotString))
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("Parser.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

// TestParser_SupportedExtensions tests the SupportedExtensions function
func TestParser_SupportedExtensions(t *testing.T) {
	tests := []struct {
		name string
		p    *Parser
		want []string
	}{
		{
			name: "Buildah extensions",
			p:    &Parser{},
			want: []string{".sh"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Parser{}
			if got := p.SupportedExtensions(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parser.SupportedExtensions() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestParser_SupportedTypes tests the SupportedTypes function
func TestParser_SupportedTypes(t *testing.T) {
	tests := []struct {
		name string
		p    *Parser
		want map[string]bool
	}{
		{
			name: "Buildah types",
			p:    &Parser{},
			want: map[string]bool{"buildah": true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Parser{}
			if got := p.SupportedTypes(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parser.SupportedTypes() = %v, want %v", got, tt.want)
			}
		})
	}
}
