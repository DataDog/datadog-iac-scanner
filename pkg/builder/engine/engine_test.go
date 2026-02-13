/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// TestEngine_BuildString tests the functions [buildString()] and all the methods called by them
func TestEngine_BuildString(t *testing.T) {
	type args struct {
		parts []hclsyntax.Expression
	}
	type fields struct {
		Engine *Engine
	}
	tests := []struct {
		name    string
		args    args
		fields  fields
		want    string
		wantErr bool
	}{
		{
			name: "build_string",
			fields: fields{
				Engine: &Engine{},
			},
			args: args{
				parts: []hclsyntax.Expression{},
			},
			want:    "",
			wantErr: false,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.fields.Engine.buildString(ctx, tt.args.parts)
			if (err != nil) != tt.wantErr {
				t.Errorf("Run() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %v, want %v", got, tt.want)
			}
		})
	}
}
