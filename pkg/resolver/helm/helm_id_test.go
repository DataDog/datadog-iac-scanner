package helm

import (
	"strings"
	"testing"

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
	file := addID(&chart.File{Name: "templates/nested.yaml", Data: []byte(original)})

	require.Contains(t, string(file.Data), "# KICS_HELM_ID_0:\napiVersion: v1")
	require.Contains(t, string(file.Data), "# KICS_HELM_ID_8:\napiVersion: v1")
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
	addID(file)

	require.Equal(t, 1, strings.Count(string(file.Data), kicsHelmID))
	require.Contains(t, string(file.Data), "  apiVersion: v1")
	require.Contains(t, string(file.Data), kicsHelmID)
}

func TestAddID_stampsIndentedRootAPIVersion(t *testing.T) {
	file := &chart.File{Data: []byte("  apiVersion: v1\n  kind: ConfigMap\n")}
	addID(file)

	require.Equal(t, 1, strings.Count(string(file.Data), kicsHelmID))
	require.Contains(t, string(file.Data), "# KICS_HELM_ID_0:\n  apiVersion: v1")
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
	addID(file)

	require.Equal(t, 8, strings.Count(string(file.Data), kicsHelmID))
}
