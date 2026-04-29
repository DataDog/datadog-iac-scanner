package kustomize

import (
	"regexp"

	"sigs.k8s.io/kustomize/api/resource"
)

// Default kustomize content-hash suffix length is 10 alphanumeric characters.
var kustomizeNameHashSuffix = regexp.MustCompile(`-[a-z0-9]{10}$`)

func stripKustomizeNameHashSuffix(name string) string {
	return kustomizeNameHashSuffix.ReplaceAllString(name, "")
}

// generatorResourceName returns the stable id for generator-produced resources (pre-hash-suffix).
// OrgId().Name may still include the content hash; strip a trailing kustomize hash when present.
func generatorResourceName(res *resource.Resource) string {
	if res == nil {
		return ""
	}
	rendered := res.GetName()
	if s := stripKustomizeNameHashSuffix(rendered); s != "" && s != rendered {
		return s
	}
	if n := res.OrgId().Name; n != "" {
		if s := stripKustomizeNameHashSuffix(n); s != "" && s != n {
			return s
		}
		return n
	}
	return rendered
}
