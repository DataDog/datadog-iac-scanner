package runner

import "regexp"

// countResourcesRegex counts top-level-looking resource blocks in raw content.
var countResourcesRegex = regexp.MustCompile(`\bresource[\s]+"[^"]+"[\s]+"[^"]+"[\s]*\{`) //nolint:gocritic // keep the pattern as written

func GetCountTerraformResources(fileContent []byte) int {
	return len(countResourcesRegex.FindAll(fileContent, -1))
}
