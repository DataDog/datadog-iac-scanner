package helm

import (
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/helmmarker"
	"github.com/stretchr/testify/require"
	"helm.sh/helm/v3/pkg/chart"
)

func TestAddID_multiDocumentUsesSourceLineIDs(t *testing.T) {
	original := strings.Join([]string{
		"apiVersion: v1",
		"kind: Service",
		"metadata:",
		"  name: nested-one",
		"spec:",
		"  ports:",
		"  - name: nested-one",
		"---",
		"apiVersion: v1",
		"kind: Service",
		"metadata:",
		"  name: nested-two",
		"spec:",
		"  ports:",
		"  - name: nested-two",
	}, "\n")
	file := addID(&chart.File{Name: "templates/nested.yaml", Data: []byte(original)}, 0)

	require.Contains(t, string(file.Data), "# KICS_HELM_ID_0_0:\napiVersion: v1")
	require.Contains(t, string(file.Data), "# KICS_HELM_ID_0_8:\napiVersion: v1")
}

func TestAddID_ignoresIndentedAPIVersion(t *testing.T) {
	original := `description: |
  apiVersion: v1
  ---
  apiVersion: v2
  kind: Pod
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
`
	file := &chart.File{Data: []byte(original)}
	addID(file, 0)

	require.Equal(t, 1, strings.Count(string(file.Data), helmmarker.IDPrefix))
	require.Contains(t, string(file.Data), "  apiVersion: v1")
	require.Contains(t, string(file.Data), helmmarker.IDPrefix)
}

func TestAddID_stampsIndentedRootAPIVersion(t *testing.T) {
	file := &chart.File{Data: []byte("  apiVersion: v1\n  kind: ConfigMap\n")}
	addID(file, 0)

	require.Equal(t, 1, strings.Count(string(file.Data), helmmarker.IDPrefix))
	require.Contains(t, string(file.Data), "# KICS_HELM_ID_0_0:\n  apiVersion: v1")
}

func TestAddID_stampsValidAPIVersionKeyStyles(t *testing.T) {
	file := &chart.File{Data: []byte(`"apiVersion": v1
kind: ConfigMap
---
'apiVersion' : v1
kind: Secret
---
{apiVersion: v1, kind: Service}
---
? apiVersion
: v1
kind: Pod
---
{
  apiVersion: v1,
  kind: ConfigMap
}
---
!tag apiVersion: v1
kind: Secret
---
&key apiVersion: v1
kind: Service
---
"api\u0056ersion": v1
kind: Pod
`)}
	file.Name = "crds/keys.yaml"
	addID(file, 0)

	require.Equal(t, 8, strings.Count(string(file.Data), helmmarker.IDPrefix))
}

// Every template of a chart and of its subcharts gets its own number, so no two
// stamps are equal even when the templates are identical.
func TestSetID_NumbersTemplatesUniquelyAcrossSubcharts(t *testing.T) {
	data := "apiVersion: v1\nkind: ConfigMap\n"
	sub := &chart.Chart{
		Metadata:  &chart.Metadata{Name: "sub"},
		Templates: []*chart.File{{Name: "templates/a.yaml", Data: []byte(data)}},
	}
	root := &chart.Chart{
		Metadata: &chart.Metadata{Name: "root"},
		Templates: []*chart.File{
			{Name: "templates/a.yaml", Data: []byte(data)},
			{Name: "templates/b.yaml", Data: []byte(data)},
		},
	}
	root.AddDependency(sub)

	sources := setID(root, noInvocationMarks)

	seen := map[string]bool{}
	for _, file := range append(append([]*chart.File{}, root.Templates...), sub.Templates...) {
		stamp := strings.SplitN(string(sources.of(file)), "\n", 2)[0]
		require.False(t, seen[stamp], "stamp %q is shared by two templates", stamp)
		seen[stamp] = true
	}
	require.Len(t, seen, 3)
}
