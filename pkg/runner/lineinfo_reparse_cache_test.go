package runner

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	iacparser "github.com/DataDog/datadog-iac-scanner/pkg/parser"
	"github.com/stretchr/testify/require"
)

func TestSharedReparseSharesOneParseAmongLayers(t *testing.T) {
	calls := 0
	reparse := func(context.Context, *model.FileMetadata) (iacparser.ParsedDocument, error) {
		calls++
		return iacparser.ParsedDocument{Docs: []model.Document{{"a": 1}, {"b": 2}}}, nil
	}
	file := &model.FileMetadata{OriginalData: "content-of-shared-reparse-test"}
	shared := sharedReparse(true, "shared_reparse_test.tf", reparse)

	ctx := model.WithSharedLineInfo(context.Background())
	for range 3 {
		_, err := shared(ctx, file)
		require.NoError(t, err)
	}
	require.Equal(t, 1, calls)

	// Outside the decode pass, and for files with a single document, every
	// load reparses on its own.
	_, err := shared(context.Background(), file)
	require.NoError(t, err)
	require.Equal(t, 2, calls)
	_, err = sharedReparse(false, "shared_reparse_test.tf", reparse)(ctx, file)
	require.NoError(t, err)
	require.Equal(t, 3, calls)
}
