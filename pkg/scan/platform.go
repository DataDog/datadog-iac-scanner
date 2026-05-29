package scan

import "strings"

// ApplyPlatformFilters intersects cliPlatforms with the only/ignore lists from
// the IaC config, returning the set of platforms that should actually be scanned.
func ApplyPlatformFilters(cliPlatforms, onlyPlatforms, ignorePlatforms []string) []string {
	active := cliPlatforms

	if len(onlyPlatforms) > 0 {
		allowed := make(map[string]struct{}, len(onlyPlatforms))
		for _, p := range onlyPlatforms {
			allowed[strings.ToLower(p)] = struct{}{}
		}
		filtered := active[:0:0]
		for _, p := range active {
			if _, ok := allowed[strings.ToLower(p)]; ok {
				filtered = append(filtered, p)
			}
		}
		active = filtered
	}

	if len(ignorePlatforms) > 0 {
		ignored := make(map[string]struct{}, len(ignorePlatforms))
		for _, p := range ignorePlatforms {
			ignored[strings.ToLower(p)] = struct{}{}
		}
		filtered := active[:0:0]
		for _, p := range active {
			if _, ok := ignored[strings.ToLower(p)]; !ok {
				filtered = append(filtered, p)
			}
		}
		active = filtered
	}

	return active
}
