package utils

import (
	"fmt"
	"strings"
	"unicode"
)

// Constants with default query values
const (
	UndetectedVulnerabilityLine = -1
	DefaultQueryID              = "Undefined"
	DefaultQueryName            = "Anonymous"
	DefaultExperimental         = false
	DefaultQueryDescription     = "Undefined"
	DefaultQueryDescriptionID   = "Undefined"
	DefaultQueryURI             = "https://github.com/DataDog/datadog-iac-scanner/"
	UnresolvedPlaceholder       = "__UNRESOLVED__"

	// RegoQuery is the OPA query evaluated against every rule module.
	RegoQuery = `result = data.datadog.DatadogPolicy`
)

func ChooseQueryID(queryID, legacyQueryID string) string {
	if legacyQueryID == DefaultQueryID {
		return queryID
	} else {
		return legacyQueryID
	}
}

func ToSlug(name string) string {
	parts := []string{}
	part := strings.Builder{}
	for _, c := range name {
		if unicode.IsUpper(c) {
			part.WriteRune(unicode.ToLower(c))
		} else if unicode.IsDigit(c) || unicode.IsLower(c) {
			part.WriteRune(c)
		} else if part.Len() > 0 {
			parts = append(parts, part.String())
			part = strings.Builder{}
		}
	}
	if part.Len() > 0 {
		parts = append(parts, part.String())
	}
	return strings.Join(parts, "-")
}

func ToID(platform, provider, dir string) string {
	if provider != "" {
		return strings.ToLower(ToSlug(fmt.Sprintf("%s-%s-%s", platform, provider, dir)))
	} else {
		return strings.ToLower(ToSlug(fmt.Sprintf("%s-%s", platform, dir)))
	}
}
