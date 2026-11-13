package utils

import (
	"fmt"
	"sort"
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

// RuleIDCandidates lists every ID a rule can be referenced by, in the order a
// rule config wins when several IDs of the same rule have keys: the canonical
// id first, then the legacy id, then the legacy_ids entries in sorted order.
func RuleIDCandidates(queryID, legacyQueryID string, legacyQueryIDs []string) []string {
	ids := make([]string, 0, 2+len(legacyQueryIDs))
	ids = append(ids, queryID)
	if legacyQueryID != "" {
		ids = append(ids, legacyQueryID)
	}
	sorted := append([]string(nil), legacyQueryIDs...)
	sort.Strings(sorted)
	return append(ids, sorted...)
}

// RuleIDMatches reports whether a user-supplied rule reference matches a rule
// by its canonical id, its legacy id, or any of its legacy_ids entries.
func RuleIDMatches(queryID, legacyQueryID string, legacyQueryIDs []string, reference string) bool {
	if reference == "" {
		return false
	}
	for _, id := range RuleIDCandidates(queryID, legacyQueryID, legacyQueryIDs) {
		if strings.EqualFold(id, reference) {
			return true
		}
	}
	return false
}

// RuleIDsFromMetadata extracts the legacy_ids entries from rule metadata,
// whichever representation the source produced: JSON unmarshaling yields
// []interface{} of strings, the Datadog API source stores []string.
func RuleIDsFromMetadata(value interface{}) []string {
	switch ids := value.(type) {
	case []string:
		return ids
	case []interface{}:
		out := make([]string, 0, len(ids))
		for _, id := range ids {
			if s, ok := id.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func ChooseQueryID(queryID, legacyQueryID string) string {
	// Empty legacy must not win: it would drop rule identity from fingerprints and dedupe keys.
	if legacyQueryID == "" || legacyQueryID == DefaultQueryID {
		return queryID
	}
	return legacyQueryID
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
