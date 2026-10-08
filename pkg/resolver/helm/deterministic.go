package helm

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/helmaction"
	"helm.sh/helm/v3/pkg/chart"
)

// notPrecededByVarOrField rejects matches that are variable references ($name) or
// field accesses (.field). Quoted-string detection is handled separately by
// helmaction.InQuote, which is more accurate than a single-byte check.
func notPrecededByVarOrField(s string, pos int) bool {
	if pos == 0 {
		return true
	}
	prev := s[pos-1]
	return prev != '$' && prev != '.'
}

// deterministicPattern represents a non-deterministic sprig function to replace.
type deterministicPattern struct {
	// keyword is a literal every match contains, checked before running re.
	keyword string
	re      *regexp.Regexp
	replace func(lineNum int) string
	// guard is an optional function that can reject a match. Returns true to accept, false to skip.
	// If nil, all matches are accepted.
	guard func(s string, matchStart int) bool
}

// deterministicPatterns maps each non-deterministic sprig function regex to a replacement generator.
// The generator receives the line number of the match.
// templateArgRE matches a Sprig function argument: a numeric literal, a .Values.foo
// field path, or a $variable reference.
const templateArgRE = `[\w$.]+`

var deterministicPatterns = []deterministicPattern{
	{
		keyword: "randAlphaNum",
		re:      regexp.MustCompile(`\brandAlphaNum\s+` + templateArgRE),
		replace: func(lineNum int) string { return fmt.Sprintf(`"ddscan%04d"`, lineNum) },
		guard:   notPrecededByVarOrField,
	},
	{
		keyword: "randAlpha",
		re:      regexp.MustCompile(`\brandAlpha\s+` + templateArgRE),
		replace: func(lineNum int) string { return fmt.Sprintf(`"ddscan%04d"`, lineNum) },
		guard:   notPrecededByVarOrField,
	},
	{
		keyword: "randAscii",
		re:      regexp.MustCompile(`\brandAscii\s+` + templateArgRE),
		replace: func(lineNum int) string { return fmt.Sprintf(`"ddscan%04d"`, lineNum) },
		guard:   notPrecededByVarOrField,
	},
	{
		keyword: "randNumeric",
		re:      regexp.MustCompile(`\brandNumeric\s+` + templateArgRE),
		replace: func(lineNum int) string { return fmt.Sprintf(`"%08d"`, lineNum) },
		guard:   notPrecededByVarOrField,
	},
	{
		keyword: "randBytes",
		re:      regexp.MustCompile(`\brandBytes\s+` + templateArgRE),
		replace: func(lineNum int) string { return fmt.Sprintf(`"ddscan%04d"`, lineNum) },
		guard:   notPrecededByVarOrField,
	},
	{
		keyword: "uuidv4",
		re:      regexp.MustCompile(`\buuidv4\b`),
		replace: func(lineNum int) string { return fmt.Sprintf(`"00000000-0000-0000-%04d-%012d"`, lineNum, lineNum) },
		guard:   notPrecededByVarOrField,
	},
	{
		keyword: "now",
		re:      regexp.MustCompile(`\bnow\b`),
		replace: func(_ int) string { return `(toDate "2006-01-02" "2000-01-01")` },
		guard:   notPrecededByVarOrField,
	},
}

// applyDeterministicSubstitutions replaces non-deterministic sprig function calls in a Helm
// template with stable, line-number-seeded stubs so that repeated renders produce identical output.
func applyDeterministicSubstitutions(data []byte) []byte {
	s := string(data)
	patterns := make([]deterministicPattern, 0, len(deterministicPatterns))
	for _, p := range deterministicPatterns {
		if strings.Contains(s, p.keyword) {
			patterns = append(patterns, p)
		}
	}
	if len(patterns) == 0 {
		return data
	}
	var replacements []replacement

	// Pre-compute the spans of all {{ ... }} action blocks so we only substitute
	// inside them, not in literal text (e.g. shell scripts in ConfigMap data).
	spans := helmaction.Code(s)

	for _, p := range patterns {
		matches := p.re.FindAllStringIndex(s, -1)
		for _, m := range matches {
			// Only substitute inside {{ ... }} action blocks.
			if !helmaction.InAny(m[0], spans) {
				continue
			}

			// Skip matches inside string literals within the action (e.g. printf "...now...").
			if helmaction.InQuote(s, m[0], spans) {
				continue
			}

			// Check guard if present (variable/field references).
			if p.guard != nil && !p.guard(s, m[0]) {
				continue
			}

			lineNum := strings.Count(s[:m[0]], "\n") + 1
			replacements = append(replacements, replacement{
				start: m[0],
				end:   m[1],
				text:  p.replace(lineNum),
			})
		}
	}

	// Apply back-to-front so earlier offsets remain valid.
	sort.Slice(replacements, func(i, j int) bool {
		return replacements[i].start > replacements[j].start
	})

	b := []byte(s)
	for _, r := range replacements {
		b = append(b[:r.start], append([]byte(r.text), b[r.end:]...)...)
	}
	return b
}

// makeDeterministic replaces all non-deterministic sprig calls in every template of the chart
// and its dependencies, making repeated renders produce identical manifests.
func makeDeterministic(ch *chart.Chart) *chart.Chart {
	for _, temp := range ch.Templates {
		temp.Data = applyDeterministicSubstitutions(temp.Data)
	}
	for _, dep := range ch.Dependencies() {
		makeDeterministic(dep)
	}
	return ch
}
