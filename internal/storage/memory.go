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
	reportmodel "github.com/DataDog/datadog-iac-scanner/pkg/report/model"
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
	sciInfo         model.SCIInfo
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
		artifactPath := v.FileName
		if artifactPath == "." {
			artifactPath = ""
		}
		ruleID := utils.ChooseQueryID(v.QueryID, v.LegacyQueryID)
		key := reportmodel.GetDatadogFingerprintHash(m.sciInfo, artifactPath, v.Platform, v.ResourceType, v.ResourceName, ruleID, v.LineWithVulnerability)
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

// NewMemoryStorage creates a new MemoryStorage empty and returns it
func NewMemoryStorage(sciInfo model.SCIInfo) *MemoryStorage {
	log.Debug().Msg("storage.NewMemoryStorage()")
	return &MemoryStorage{
		allFiles:        make(model.FileMetadatas, 0),
		vulnerabilities: make([]model.Vulnerability, 0),
		sciInfo:         sciInfo,
	}
}
