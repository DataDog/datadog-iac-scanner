package kics

import "regexp"

func GetCountTerraformResources(fileContent []byte) int {
	// nolint:gocritic
	re := regexp.MustCompile(`\bresource[\s]+"[^"]+"[\s]+"[^"]+"[\s]*\{`)
	matches := re.FindAll(fileContent, -1)

	return len(matches)
}
