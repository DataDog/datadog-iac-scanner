package utils

func ChooseQueryID(queryID, legacyQueryID string) string {
	if legacyQueryID == "Undefined" {
		return queryID
	} else {
		return legacyQueryID
	}
}
