package source

import "strings"

// PlatformUnknown is the sentinel GetPlatform returns for an unrecognized
// backend platform name.
const PlatformUnknown = "unknown"

type supportedPlatforms map[string]string

var supPlatforms = &supportedPlatforms{
	"Ansible":                 "ansible",
	"CloudFormation":          "cloudFormation",
	"Common":                  "common",
	"Crossplane":              "crossplane",
	"Dockerfile":              "dockerfile",
	"Knative":                 "knative",
	"Kubernetes":              "k8s",
	"OpenAPI":                 "openAPI",
	"Terraform":               "terraform",
	"AzureResourceManager":    "azureResourceManager",
	"GRPC":                    "grpc",
	"GoogleDeploymentManager": "googleDeploymentManager",
	"Buildah":                 "buildah",
	"Pulumi":                  "pulumi",
	"ServerlessFW":            "serverlessFW",
	"CICD":                    "cicd",
}

// GetPlatform maps a backend platform name (e.g. "Kubernetes") to the engine's
// platform key (e.g. "k8s"), returning "unknown" when unrecognized.
func GetPlatform(metadataPlatform string) string {
	if p, ok := (*supPlatforms)[metadataPlatform]; ok {
		return p
	}
	return PlatformUnknown
}

// LibraryName maps a user-facing platform name (case-insensitive) to the
// embedded library file name under assets/libraries/. Returns the lower-cased
// input unchanged when no specific mapping exists.
func LibraryName(platform string) string {
	for key, lib := range *supPlatforms {
		if strings.EqualFold(key, platform) {
			return lib
		}
	}
	return strings.ToLower(platform)
}
