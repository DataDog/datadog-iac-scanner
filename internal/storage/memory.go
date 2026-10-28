/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package storage

import (
	"context"
	"crypto/sha256"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
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
	if len(m.vulnerabilities) == 0 {
		// Cap so a later append cannot write into the caller's spare capacity.
		m.vulnerabilities = vulnerabilities[:len(vulnerabilities):len(vulnerabilities)]
		return nil
	}
	m.vulnerabilities = append(m.vulnerabilities, vulnerabilities...)
	return nil
}

// GetVulnerabilities returns a collection of vulnerabilities saved on MemoryStorage
func (m *MemoryStorage) GetVulnerabilities(_ context.Context, _ string) ([]model.Vulnerability, error) {
	memoryMu.Lock()
	defer memoryMu.Unlock()
	return m.getUniqueVulnerabilities(), nil
}

// getUniqueVulnerabilities keeps the last finding of each identity. Storage
// returns them in the order they were saved; reports may sort them again. It
// compacts in place so the findings are not held twice, which leaves an
// already deduplicated collection as it is.
func (m *MemoryStorage) getUniqueVulnerabilities() []model.Vulnerability {
	seen := make(map[[sha256.Size]byte]struct{}, len(m.vulnerabilities))
	write := len(m.vulnerabilities) - 1
	for i := write; i >= 0; i-- {
		digest := sha256.Sum256([]byte(model.FindingIdentity(&m.vulnerabilities[i])))
		if _, duplicate := seen[digest]; duplicate {
			continue
		}
		seen[digest] = struct{}{}
		m.vulnerabilities[write] = m.vulnerabilities[i]
		write--
	}
	unique := m.vulnerabilities[write+1:]
	copy(m.vulnerabilities, unique)
	clear(m.vulnerabilities[len(unique):])
	m.vulnerabilities = m.vulnerabilities[:len(unique)]
	return m.vulnerabilities
}

// NewMemoryStorage creates a new MemoryStorage empty and returns it
func NewMemoryStorage() *MemoryStorage {
	log.Debug().Msg("storage.NewMemoryStorage()")
	return &MemoryStorage{
		allFiles:        make(model.FileMetadatas, 0),
		vulnerabilities: make([]model.Vulnerability, 0),
	}
}
