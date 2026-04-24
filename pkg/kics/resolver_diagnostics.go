package kics

import (
	"context"
	"os"
	"path/filepath"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

type ResolverDiagnosticsState struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

func NewResolverDiagnosticsState() *ResolverDiagnosticsState {
	return &ResolverDiagnosticsState{
		seen: make(map[string]struct{}),
	}
}

func (s *ResolverDiagnosticsState) FirstSeen(scanID string, d model.ResolverDiagnostic) bool {
	if s == nil {
		return true
	}
	key := resolverDiagnosticDedupKey(scanID, d)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[key]; ok {
		return false
	}
	s.seen[key] = struct{}{}
	return true
}

func (s *Service) saveResolverDiagnostics(ctx context.Context, scanID string, diags []model.ResolverDiagnostic) error {
	if len(diags) == 0 {
		return nil
	}
	var vulns []model.Vulnerability
	for _, d := range diags {
		if s.ResolverDiagnostics != nil && !s.ResolverDiagnostics.FirstSeen(scanID, d) {
			continue
		}
		line := d.Line
		if line < 1 {
			line = 1
		}
		vulns = append(vulns, model.Vulnerability{
			ScanID:    scanID,
			QueryID:   d.QueryID,
			QueryName: resolverDiagnosticQueryName(d.QueryID),
			FileName:  d.FilePath,
			Line:      line,
			VulnerabilityLocation: model.ResourceLocation{
				Start: model.ResourceLine{Line: line, Col: 1},
				End:   model.ResourceLine{Line: line, Col: 1},
			},
			Severity:    model.SeverityInfo,
			Category:    "Resolver",
			Description: d.Message,
			Platform:    resolverDiagnosticPlatform(s, d),
			IssueType:   model.IssueTypeIncorrectValue,
			SearchKey:   "resolver_diagnostic." + d.QueryID,
			SearchLine:  line,
			SearchValue: d.Message,
		})
	}
	if len(vulns) == 0 {
		return nil
	}
	return s.Storage.SaveVulnerabilities(ctx, vulns)
}

func resolverDiagnosticPlatform(s *Service, d model.ResolverDiagnostic) string {
	if d.QueryID == "" {
		if s == nil || s.Parser == nil || len(s.Parser.Platform) == 0 {
			return ""
		}
		return s.Parser.Platform[0]
	}
	if s != nil && s.Resolver != nil {
		targetPath := d.FilePath
		if targetPath != "" {
			if info, err := os.Stat(targetPath); err == nil && !info.IsDir() {
				targetPath = filepath.Dir(targetPath)
			}
		}
		switch s.Resolver.GetType(targetPath) {
		case model.KindKUSTOMIZE, model.KindHELM:
			return "Kubernetes"
		}
	}
	if s == nil || s.Parser == nil || len(s.Parser.Platform) == 0 {
		return ""
	}
	return s.Parser.Platform[0]
}

func resolverDiagnosticDedupKey(scanID string, d model.ResolverDiagnostic) string {
	return joinNull(scanID, d.QueryID, d.FilePath, d.Message, itoaOrZero(d.Line))
}

func joinNull(parts ...string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for i := 1; i < len(parts); i++ {
		out += "\x00" + parts[i]
	}
	return out
}

func itoaOrZero(v int) string {
	if v == 0 {
		return "0"
	}
	sign := ""
	if v < 0 {
		sign = "-"
		v = -v
	}
	var digits [20]byte
	i := len(digits)
	for v > 0 {
		i--
		digits[i] = byte('0' + v%10)
		v /= 10
	}
	return sign + string(digits[i:])
}
