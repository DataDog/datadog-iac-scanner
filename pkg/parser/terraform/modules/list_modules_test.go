package tfmodules

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestListModuleEntriesJSONShape(t *testing.T) {
	entries := ListModuleEntries(map[string]ParsedModule{
		"k": {
			Name:          "vpc",
			Source:        "terraform-aws-modules/vpc/aws",
			Version:       "5.0.0",
			SourceType:    "registry",
			RegistryScope: "public",
			FileName:      "/repo/main.tf",
			DefLine:       12,
		},
	}, false)

	require.Len(t, entries, 1)
	data, err := json.Marshal(entries)
	require.NoError(t, err)

	var raw []map[string]any
	require.NoError(t, json.Unmarshal(data, &raw))
	require.Len(t, raw, 1)

	row := raw[0]
	require.Equal(t, "vpc", row["name"])
	require.Equal(t, "terraform-aws-modules/vpc/aws", row["source"])
	require.Equal(t, "5.0.0", row["version"])
	require.Equal(t, "registry", row["source_type"])
	require.Equal(t, "public", row["registry_scope"])
	require.Equal(t, "/repo/main.tf", row["file_name"])
	require.Equal(t, float64(12), row["def_line"])
	require.Equal(t, "/repo/main.tf", row["caller_path"])
	require.NotEmpty(t, row["call_id"])
}

func TestListModuleEntriesSkipsLocalByDefault(t *testing.T) {
	entries := ListModuleEntries(map[string]ParsedModule{
		"k": {Name: "local", Source: "./modules/vpc", IsLocal: true},
	}, false)
	require.Empty(t, entries)

	entries = ListModuleEntries(map[string]ParsedModule{
		"k": {Name: "local", Source: "./modules/vpc", IsLocal: true, SourceType: "local"},
	}, true)
	require.Len(t, entries, 1)
	require.Equal(t, "local", entries[0].Name)
}

func TestListModuleEntriesUsesStableRepositoryRelativeCallID(t *testing.T) {
	module := ParsedModule{
		Name:     "vpc",
		Source:   "terraform-aws-modules/vpc/aws",
		Version:  "~> 5.0",
		FileName: filepath.Join("/checkout-a", "infra", "main.tf"),
		DefLine:  12,
	}
	first := ListModuleEntriesRelativeTo(
		map[string]ParsedModule{"a": module}, false, "/checkout-a",
	)
	module.FileName = filepath.Join("/checkout-b", "infra", "main.tf")
	second := ListModuleEntriesRelativeTo(
		map[string]ParsedModule{"a": module}, false, "/checkout-b",
	)

	require.Equal(t, "infra/main.tf", first[0].CallerPath)
	require.Equal(t, "/checkout-a", first[0].CallerPathBase)
	require.Equal(t, "/checkout-b", second[0].CallerPathBase)
	require.Equal(t, first[0].CallerPath, second[0].CallerPath)
	require.Equal(t, first[0].CallID, second[0].CallID)
}
