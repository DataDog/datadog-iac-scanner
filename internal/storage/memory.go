/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package storage

import (
	"context"
	"sort"
	"strings"
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

// instanceKey tells apart the findings of distinct instances of one Terraform
// block. Instances share the block's file, line and call chain, and its name
// when a rule reports the block name, so the fingerprint alone would merge
// them. An instantiated document's id, "<file id>\x00<call chain>\x00<layer>",
// is unique per instance of each block it holds; other documents add nothing.
func instanceKey(v *model.Vulnerability) string {
	if strings.Contains(v.FileID, "\x00") {
		return "\x00" + v.FileID
	}
	return ""
}

func (m *MemoryStorage) getUniqueVulnerabilities() []model.Vulnerability {
	// The last finding saved under a key is kept. Keys map to positions rather
	// than to copies of the findings, which a large scan holds hundreds of
	// thousands of.
	last := make(map[string]int, len(m.vulnerabilities))
	for i := range m.vulnerabilities {
		v := &m.vulnerabilities[i]
		fileName, line := v.Identity()
		// SCIInfo is constant within a scan; an empty value yields the same grouping.
		key := model.GetDatadogFingerprintHash(
			model.SCIInfo{},
			fileName,
			v.Platform,
			v.ResourceType,
			v.ResourceName,
			utils.ChooseQueryID(v.QueryID, v.LegacyQueryID),
			line,
			v.ModuleCallChain,
		) + instanceKey(v)
		last[key] = i
	}
	if len(last) == 0 {
		return m.vulnerabilities
	}
	keep := make([]int, 0, len(last))
	for _, i := range last {
		keep = append(keep, i)
	}
	sort.Ints(keep)
	uniqueVulnerabilities := make([]model.Vulnerability, len(keep))
	for j, i := range keep {
		uniqueVulnerabilities[j] = m.vulnerabilities[i]
	}
	return uniqueVulnerabilities
}

// NewMemoryStorage creates a new MemoryStorage empty and returns it
func NewMemoryStorage() *MemoryStorage {
	log.Debug().Msg("storage.NewMemoryStorage()")
	return &MemoryStorage{
		allFiles:        make(model.FileMetadatas, 0),
		vulnerabilities: make([]model.Vulnerability, 0),
	}
}
