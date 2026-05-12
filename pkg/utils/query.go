package utils

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

	RegoQuery = `result = data.Cx.CxPolicy`
)

func ChooseQueryID(queryID, legacyQueryID string) string {
	if legacyQueryID == DefaultQueryID {
		return queryID
	} else {
		return legacyQueryID
	}
}
