package kics

// Stable human-readable titles for resolver diagnostics (no Rego metadata).
var resolverDiagnosticTitles = map[string]string{
	"kustomize-render-failed":             "Kustomize render failed",
	"kustomize-remote-disallowed":         "Kustomize remote reference blocked",
	"kustomize-max-fetch-exceeded":        "Kustomize scratch size limit exceeded",
	"kustomize-exec-plugin-disabled":      "Kustomize exec-style plugins disabled",
	"kustomize-helm-inflation-disabled":   "Kustomize Helm inflation disabled",
	"kustomize-helm-prepass-failed":       "Kustomize Helm prepass failed",
	"kustomize-helm-chart-missing":        "Kustomize Helm chart missing",
	"kustomize-helm-remote-chart-invalid": "Kustomize Helm remote chart invalid",
	"kustomize-helm-values-invalid":       "Kustomize Helm values invalid",
	"kustomize-helm-render-failed":        "Kustomize Helm chart render failed",
	"kustomize-helm-write-failed":         "Kustomize Helm rendered manifest write failed",
	"kustomize-transformer-path-missing":  "Kustomize transformer patch path missing",
}

func resolverDiagnosticQueryName(queryID string) string {
	if t, ok := resolverDiagnosticTitles[queryID]; ok {
		return t
	}
	return "IaC resolver notice: " + queryID
}
