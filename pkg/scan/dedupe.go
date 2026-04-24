package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// dedupeKustomizeOverlappingFindings collapses duplicates when several kustom roots render the same resource (shared base).
// Caller must only invoke when the scan used Kustomize-rendered files (see executeScan). Keys include FileName and diagnostic text;
// tie-break uses preferLikelyOverlay (lexicographic on paths when FileName matches).
func dedupeKustomizeOverlappingFindings(vulns []model.Vulnerability, files model.FileMetadatas) []model.Vulnerability {
	if len(vulns) <= 1 {
		return vulns
	}
	kustomizeOriginFileIDs := kustomizeOriginFileIDs(files)
	keep := make(map[string]model.Vulnerability)
	out := make([]model.Vulnerability, 0, len(vulns))
	for _, v := range vulns {
		if !isKustomizeOriginFinding(v, kustomizeOriginFileIDs) {
			out = append(out, v)
			continue
		}
		key := kustomizeOverlapDedupeKey(v)
		existing, ok := keep[key]
		if !ok {
			keep[key] = v
			continue
		}
		if preferLikelyOverlay(v.FileName, existing.FileName) {
			keep[key] = v
		}
	}
	for _, v := range keep {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].QueryID != out[j].QueryID {
			return out[i].QueryID < out[j].QueryID
		}
		if out[i].FileName != out[j].FileName {
			return out[i].FileName < out[j].FileName
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].ResourceName < out[j].ResourceName
	})
	return out
}

func kustomizeOverlapDedupeKey(v model.Vulnerability) string {
	h := sha256.New()
	_, _ = h.Write([]byte(v.QueryID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(v.FileName))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(v.ResourceType))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(v.SearchKey))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(v.ResourceName))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(strconv.Itoa(v.Line)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(v.Description))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(v.SearchValue))
	return hex.EncodeToString(h.Sum(nil))
}

func preferLikelyOverlay(a, b string) bool {
	if len(a) != len(b) {
		return len(a) > len(b)
	}
	if a < b {
		return true
	}
	return false
}

func isKustomizeOriginFinding(v model.Vulnerability, originFileIDs map[string]struct{}) bool {
	if len(v.SearchKey) >= len("resolver_diagnostic.kustomize-") && v.SearchKey[:len("resolver_diagnostic.kustomize-")] == "resolver_diagnostic.kustomize-" {
		return true
	}
	_, ok := originFileIDs[v.FileID]
	return ok
}

func kustomizeOriginFileIDs(files model.FileMetadatas) map[string]struct{} {
	out := make(map[string]struct{})
	for _, f := range files {
		if f == nil || f.KustomizeOrigin == nil || f.ID == "" {
			continue
		}
		out[f.ID] = struct{}{}
	}
	return out
}
