package scan

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

func TestDedupeKustomizeOverlappingFindings_differentFilesNotMerged(t *testing.T) {
	v := []model.Vulnerability{
		{QueryID: "q1", FileName: "/repo/apps/a.yaml", Line: 3, SearchKey: "a.b", ResourceName: "n", ResourceType: "t"},
		{QueryID: "q1", FileName: "/repo/apps/b.yaml", Line: 3, SearchKey: "a.b", ResourceName: "n", ResourceType: "t"},
	}
	out := dedupeKustomizeOverlappingFindings(v, nil)
	require.Len(t, out, 2)
}

func TestDedupeKustomizeOverlappingFindings_keepsLongerPathSameFile(t *testing.T) {
	// Same logical match mapped to the same resolved path twice (e.g. duplicate pipeline rows).
	v := []model.Vulnerability{
		{QueryID: "q1", FileID: "k1", FileName: "/repo/k/kustomization.yaml", Line: 3, SearchKey: "a.b", ResourceName: "n", ResourceType: "t"},
		{QueryID: "q1", FileID: "k2", FileName: "/repo/k/kustomization.yaml", Line: 3, SearchKey: "a.b", ResourceName: "n", ResourceType: "t"},
	}
	out := dedupeKustomizeOverlappingFindings(v, model.FileMetadatas{
		{ID: "k1", FilePath: "/repo/k/kustomization.yaml", KustomizeOrigin: &model.KustomizeOrigin{OriginKind: model.KustomizeOriginTransformer}},
		{ID: "k2", FilePath: "/repo/k/kustomization.yaml", KustomizeOrigin: &model.KustomizeOrigin{OriginKind: model.KustomizeOriginTransformer}},
	})
	require.Len(t, out, 1)
}

func TestDedupeKustomizeOverlappingFindings_deterministicOrder(t *testing.T) {
	v := []model.Vulnerability{
		{QueryID: "z", FileName: "/a/x.yaml", Line: 1, SearchKey: "k", ResourceName: "n", ResourceType: "t"},
		{QueryID: "a", FileName: "/b/y.yaml", Line: 1, SearchKey: "k", ResourceName: "n", ResourceType: "t"},
	}
	out := dedupeKustomizeOverlappingFindings(v, nil)
	require.Len(t, out, 2)
	require.Equal(t, "a", out[0].QueryID)
	require.Equal(t, "z", out[1].QueryID)
}

func TestDedupeKustomizeOverlappingFindings_distinctDiagnosticPayloadsNotMerged(t *testing.T) {
	v := []model.Vulnerability{
		{
			QueryID:     "kustomize-transformer-path-missing",
			FileName:    "/repo/kustomization.yaml",
			Line:        1,
			Description: "transformer patch not found at \"/repo/base/a.yaml\"",
			SearchValue: "transformer patch not found at \"/repo/base/a.yaml\"",
		},
		{
			QueryID:     "kustomize-transformer-path-missing",
			FileName:    "/repo/kustomization.yaml",
			Line:        1,
			Description: "transformer patch not found at \"/repo/base/b.yaml\"",
			SearchValue: "transformer patch not found at \"/repo/base/b.yaml\"",
		},
	}
	out := dedupeKustomizeOverlappingFindings(v, nil)
	require.Len(t, out, 2)
}

func TestDedupeKustomizeOverlappingFindings_nonKustomizeFindingsNotCollapsed(t *testing.T) {
	v := []model.Vulnerability{
		{
			QueryID:      "q1",
			FileName:     "/repo/plain.yaml",
			Line:         7,
			SearchKey:    "spec.template.spec.containers[0].image",
			ResourceName: "app",
			ResourceType: "Deployment",
		},
		{
			QueryID:      "q1",
			FileName:     "/repo/plain.yaml",
			Line:         7,
			SearchKey:    "spec.template.spec.containers[0].image",
			ResourceName: "app",
			ResourceType: "Deployment",
		},
	}
	out := dedupeKustomizeOverlappingFindings(v, nil)
	require.Len(t, out, 2)
}

func TestDedupeKustomizeOverlappingFindings_sharedDirectBaseFileMerged(t *testing.T) {
	v := []model.Vulnerability{
		{QueryID: "q1", FileID: "k1", FileName: "/repo/base/deployment.yaml", Line: 7, SearchKey: "spec.template.spec.containers[0].image", ResourceName: "app", ResourceType: "Deployment"},
		{QueryID: "q1", FileID: "k2", FileName: "/repo/base/deployment.yaml", Line: 7, SearchKey: "spec.template.spec.containers[0].image", ResourceName: "app", ResourceType: "Deployment"},
	}
	files := model.FileMetadatas{
		{ID: "k1", FilePath: "/repo/base/deployment.yaml", KustomizeOrigin: &model.KustomizeOrigin{OriginKind: model.KustomizeOriginDirect}},
		{ID: "k2", FilePath: "/repo/base/deployment.yaml", KustomizeOrigin: &model.KustomizeOrigin{OriginKind: model.KustomizeOriginDirect}},
	}
	out := dedupeKustomizeOverlappingFindings(v, files)
	require.Len(t, out, 1)
}

func TestDedupeKustomizeOverlappingFindings_rawAndRenderedSamePathBothKept(t *testing.T) {
	v := []model.Vulnerability{
		{QueryID: "q1", FileID: "raw1", FileName: "/repo/base/deployment.yaml", Line: 7, SearchKey: "spec.template.spec.containers[0].image", ResourceName: "app", ResourceType: "Deployment"},
		{QueryID: "q1", FileID: "k1", FileName: "/repo/base/deployment.yaml", Line: 7, SearchKey: "spec.template.spec.containers[0].image", ResourceName: "app", ResourceType: "Deployment"},
	}
	files := model.FileMetadatas{
		{ID: "raw1", FilePath: "/repo/base/deployment.yaml"},
		{ID: "k1", FilePath: "/repo/base/deployment.yaml", KustomizeOrigin: &model.KustomizeOrigin{OriginKind: model.KustomizeOriginDirect}},
	}
	out := dedupeKustomizeOverlappingFindings(v, files)
	require.Len(t, out, 2)
}

func TestScanIncludesKustomizeFiles(t *testing.T) {
	require.False(t, scanIncludesKustomizeFiles(model.FileMetadatas{
		{Kind: model.KindYAML},
	}))
	require.True(t, scanIncludesKustomizeFiles(model.FileMetadatas{
		{Kind: model.KindYAML},
		{Kind: model.KindKUSTOMIZE},
	}))
}
