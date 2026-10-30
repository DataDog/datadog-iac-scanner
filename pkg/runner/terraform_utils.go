package runner

import "regexp"

// countResourcesRegex counts top-level-looking resource blocks in raw content.
// It is compiled once: GetCountTerraformResources runs for every scanned
// Terraform file, and compiling per call was a measurable share of the
// prepare phase.
var countResourcesRegex = regexp.MustCompile(`\bresource[\s]+"[^"]+"[\s]+"[^"]+"[\s]*\{`) //nolint:gocritic // keep the pattern as written

func GetCountTerraformResources(fileContent []byte) int {
	return len(countResourcesRegex.FindAll(fileContent, -1))
}
