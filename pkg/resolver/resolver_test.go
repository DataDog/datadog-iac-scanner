package resolver

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/resolver/helm"
)

func initializeBuilder() *Resolver {
	ctx := context.Background()
	bd, _ := NewBuilder().
		Add(ctx, helm.NewResolver(nil)).
		Build(ctx)
	return bd
}

func TestGetType(t *testing.T) {
	res := initializeBuilder()
	type args struct {
		filepath string
	}
	tests := []struct {
		name string
		args args
		want model.FileKind
	}{
		{
			name: "get_no_type",
			args: args{
				filepath: filepath.FromSlash("../../test/fixtures/all_auth_users_get_read_access"),
			},
			want: model.KindCOMMON,
		},
		{
			name: "application_helm_chart_returns_helm_kind",
			args: args{
				filepath: filepath.FromSlash("../../test/fixtures/test_helm"),
			},
			want: model.KindHELM,
		},
		{
			name: "library_helm_chart_returns_common_kind",
			args: args{
				filepath: filepath.FromSlash("../../test/fixtures/test_helm_library"),
			},
			want: model.KindCOMMON,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := res.GetType(tt.args.filepath)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetType() = %v, want = %v", got, tt.want)
			}
		})
	}
}

// TestGetTypeWithoutHelmResolver pins the Helm-flag-off shape: with no Helm
// resolver registered, nothing claims a chart directory.
func TestGetTypeWithoutHelmResolver(t *testing.T) {
	res, err := NewBuilder().Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := res.GetType(filepath.FromSlash("../../test/fixtures/test_helm")); got != model.KindCOMMON {
		t.Errorf("GetType() = %v, want %v", got, model.KindCOMMON)
	}
}
