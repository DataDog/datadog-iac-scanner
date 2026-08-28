package tfmodules

import (
	"encoding/json"
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
			DefEndLine:    18,
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
	require.Equal(t, float64(18), row["def_end_line"])
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
