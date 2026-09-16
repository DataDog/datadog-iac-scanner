/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package storage

import (
	"context"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/rs/zerolog/log"
)

var (
	memoryMu sync.Mutex
)

// MemoryStorage is scans' results representation
type MemoryStorage struct {
	vulnerabilities []model.Vulnerability
	allFiles        model.FileMetadatas
}

// SaveFile adds a new file metadata to files collection
func (m *MemoryStorage) SaveFile(_ context.Context, metadata *model.FileMetadata) error {
	memoryMu.Lock()
	defer memoryMu.Unlock()
	m.allFiles = append(m.allFiles, metadata)
	return nil
}

// GetFiles returns a collection of files saved on MemoryStorage
func (m *MemoryStorage) GetFiles(_ context.Context, _ string) (model.FileMetadatas, error) {
	memoryMu.Lock()
	defer memoryMu.Unlock()
	return m.allFiles, nil
}

// SaveVulnerabilities adds a list of vulnerabilities to vulnerabilities collection
func (m *MemoryStorage) SaveVulnerabilities(_ context.Context, vulnerabilities []model.Vulnerability) error {
	defer memoryMu.Unlock()
	memoryMu.Lock()
	m.vulnerabilities = append(m.vulnerabilities, vulnerabilities...)
	return nil
}

// GetVulnerabilities returns a collection of vulnerabilities saved on MemoryStorage
func (m *MemoryStorage) GetVulnerabilities(_ context.Context, _ string) ([]model.Vulnerability, error) {
	memoryMu.Lock()
	defer memoryMu.Unlock()
	return m.getUniqueVulnerabilities(), nil
}

func (m *MemoryStorage) getUniqueVulnerabilities() []model.Vulnerability {
	vulnDictionary := make(map[string]model.Vulnerability)
	for i := range m.vulnerabilities {
		v := m.vulnerabilities[i]
		// SCIInfo is constant within a scan; an empty value yields the same grouping.
		//
		// FileID is deliberately excluded: an HCL-sourced and a TFPlan-sourced finding for the
		// same resource are the same real-world finding once TFPlan-to-HCL mapping resolves both
		// to the same FileName/line - collapsing them here is the point, not a bug. See
		// mergeVulnerability below for which of the two survives and why.
		key := model.GetDatadogFingerprintHash(
			model.SCIInfo{},
			v.FileName,
			v.Platform,
			v.ResourceType,
			v.ResourceName,
			utils.ChooseQueryID(v.QueryID, v.LegacyQueryID),
			v.LineWithVulnerability,
			v.ModuleCallChain,
		)
		if existing, ok := vulnDictionary[key]; ok {
			vulnDictionary[key] = mergeVulnerability(existing, v)
			continue
		}
		vulnDictionary[key] = v
	}

	var uniqueVulnerabilities []model.Vulnerability
	for key := range vulnDictionary {
		uniqueVulnerabilities = append(uniqueVulnerabilities, vulnDictionary[key])
	}
	if len(uniqueVulnerabilities) == 0 {
		return m.vulnerabilities
	}
	return uniqueVulnerabilities
}

// mergeVulnerability resolves a fingerprint collision between two findings. Most collisions are
// ordinary duplicates from the same detection path (e.g. count/for_each instances collapsing to
// one resource-level finding) and either side is equivalent. The one case that isn't
// interchangeable is an HCL-sourced finding colliding with a TFPlan-sourced finding for the same
// resource - which happens once TFPlan-to-HCL mapping resolves both to the same file/line - where
// the TFPlan-sourced finding wins: its Value reflects the actually-computed plan value rather
// than the static HCL text, which is strictly more informative when the two differ (e.g. the
// value depends on a variable or interpolation the HCL-only path can't evaluate). The surviving
// record is marked TerraformSourceTFPlanHCL so it's traceable as a merge, not a plain TFPlan
// finding. That specific case is also logged so the drop is traceable rather than silent.
func mergeVulnerability(existing, incoming model.Vulnerability) model.Vulnerability {
	if existing.TerraformSource == incoming.TerraformSource {
		return incoming
	}

	kept, dropped := existing, incoming
	if incoming.TerraformSource == model.TerraformSourceTFPlan {
		kept, dropped = incoming, existing
	}
	kept.TerraformSource = model.TerraformSourceTFPlanHCL
	log.Debug().
		Str("resourceType", kept.ResourceType).
		Str("resourceName", kept.ResourceName).
		Str("fileName", kept.FileName).
		Str("queryID", utils.ChooseQueryID(kept.QueryID, kept.LegacyQueryID)).
		Str("keptFileID", kept.FileID).
		Str("droppedFileID", dropped.FileID).
		Msg("storage: HCL and TFPlan findings for the same resource merged; kept the TFPlan-sourced finding")
	return kept
}

// NewMemoryStorage creates a new MemoryStorage empty and returns it
func NewMemoryStorage() *MemoryStorage {
	log.Debug().Msg("storage.NewMemoryStorage()")
	return &MemoryStorage{
		allFiles:        make(model.FileMetadatas, 0),
		vulnerabilities: make([]model.Vulnerability, 0),
	}
}
