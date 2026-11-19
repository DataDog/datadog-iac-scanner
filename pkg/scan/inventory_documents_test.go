/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package scan

import (
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/inventory"
	"github.com/stretchr/testify/require"
)

const inventoryK8sYAML = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: shop
spec:
  replicas: 1
---
# the service
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: shop
spec:
  ports:
    - port: 80
`

const inventoryDockerfile = `FROM golang:1.23 AS build
WORKDIR /src
COPY . .
RUN go build -o /out/api ./cmd/api

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/api /api
EXPOSE 8080
ENTRYPOINT ["/api"]
`

func documentParams(root string) *Parameters {
	return &Parameters{
		Path:             []string{root},
		RepoPath:         root,
		QueriesPath:      []string{"."},
		PreviewLines:     3,
		CloudProvider:    []string{""},
		Platform:         []string{"Kubernetes", "Dockerfile"},
		ScanID:           "console",
		MaxFileSizeFlag:  100,
		MaxResolverDepth: 15,
		FlagEvaluator:    featureflags.NewLocalEvaluator(),
	}
}

func TestInventoryKubernetesAndDockerfileRows(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"k8s/web.yaml":                         inventoryK8sYAML,
		"charts/api/Chart.yaml":                "apiVersion: v2\nname: api\nversion: 0.1.0\n",
		"charts/api/values.yaml":               "replicas: 2\n",
		"charts/api/templates/deployment.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .Release.Name }}-{{ .Chart.Name }}\nspec:\n  replicas: {{ .Values.replicas }}\n",
		"services/api/Dockerfile":              inventoryDockerfile,
	})
	inv := scanInventory(t, documentParams(root))
	rows := rowsByPath(inv)

	require.Equal(t, inventory.Resource{
		ResourceRef:  "k8s/web.yaml|apps/v1/Deployment/shop/web",
		ResourcePath: "apps/v1/Deployment/shop/web",
		Platform:     "kubernetes",
		ResourceType: "Deployment",
		ResourceName: "web",
		File:         "k8s/web.yaml",
		LineStart:    1,
		LineEnd:      7,
		Completeness: inventory.CompletenessComplete,
	}, rows["apps/v1/Deployment/shop/web"])

	service := rows["v1/Service/shop/web"]
	require.Equal(t, lineOf(t, inventoryK8sYAML, "apiVersion: v1"), service.LineStart)
	require.Equal(t, lineOf(t, inventoryK8sYAML, "- port: 80"), service.LineEnd)

	helm, ok := rows["apps/v1/Deployment//dd-helm-api"]
	require.True(t, ok, "rows: %v", rows)
	require.Equal(t, inventory.Resource{
		ResourceRef:        "charts/api/templates/deployment.yaml|apps/v1/Deployment//dd-helm-api",
		ResourcePath:       "apps/v1/Deployment//dd-helm-api",
		Platform:           "kubernetes",
		ResourceType:       "Deployment",
		ResourceName:       "dd-helm-api",
		File:               "charts/api/templates/deployment.yaml",
		LineStart:          1,
		Completeness:       inventory.CompletenessComplete,
		OriginGenerator:    "helm",
		OriginChartPath:    "charts/api",
		OriginChartName:    "api",
		OriginChartVersion: "0.1.0",
		OriginTemplate:     "templates/deployment.yaml",
	}, helm)

	require.Equal(t, inventory.Resource{
		ResourceRef:  "services/api/Dockerfile|Dockerfile",
		ResourcePath: "Dockerfile",
		Platform:     "dockerfile",
		ResourceType: "dockerfile",
		ResourceName: "Dockerfile",
		File:         "services/api/Dockerfile",
		LineStart:    1,
		LineEnd:      lineOf(t, inventoryDockerfile, "ENTRYPOINT"),
		Completeness: inventory.CompletenessComplete,
	}, rows["Dockerfile"])
	require.Len(t, inv.Resources, 4)
}

func TestInventoryDoesNotChangeDocumentFindings(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"k8s/web.yaml":            inventoryK8sYAML,
		"services/api/Dockerfile": inventoryDockerfile,
	})
	without := scanSARIF(t, *documentParams(root))
	with := *documentParams(root)
	with.InventoryPath = filepath.Join(t.TempDir(), "inventory.json")
	require.Equal(t, without, scanSARIF(t, with))
}
