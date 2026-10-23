/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package model

import (
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// FixCache builds the fixes of one report's findings, each distinct one once.
// The instances of a module resource are findings at the same place in the
// same file, so they all have the same fix.
type FixCache struct {
	fixes map[fixKey]cachedFix
}

// fixKey holds every field of a finding a fix is built from. The file source
// is told apart by identity: findings of one file share it.
type fixKey struct {
	remediation, remediationType    string
	fileName, lineWithVulnerability string
	line                            int
	blockStart, blockEnd            int
	remediationStart                int
	fileSource                      *string
	fileSourceLines                 int
	start, end                      model.SarifResourceLocation
}

type cachedFix struct {
	fix model.SarifFix
	err error
}

// NewFixCache returns an empty FixCache.
func NewFixCache() *FixCache {
	return &FixCache{fixes: make(map[fixKey]cachedFix)}
}

// TransformToSarifFix is the package's TransformToSarifFix, returning the
// fix already built for a finding with the same fields. A fix returned is
// shared, and must only be read.
// nolint:gocritic
func (c *FixCache) TransformToSarifFix(ctx context.Context, vuln model.VulnerableFile,
	startLocation, endLocation model.SarifResourceLocation) (model.SarifFix, error) {
	key := fixKey{
		remediation:           vuln.Remediation,
		remediationType:       vuln.RemediationType,
		fileName:              vuln.FileName,
		lineWithVulnerability: vuln.LineWithVulnerability,
		line:                  vuln.Line,
		blockStart:            vuln.BlockLocation.Start.Line,
		blockEnd:              vuln.BlockLocation.End.Line,
		remediationStart:      vuln.RemediationLocation.Start.Line,
		fileSourceLines:       len(vuln.FileSource),
		start:                 startLocation,
		end:                   endLocation,
	}
	if len(vuln.FileSource) > 0 {
		key.fileSource = &vuln.FileSource[0]
	}
	if cached, ok := c.fixes[key]; ok {
		return cached.fix, cached.err
	}
	fix, err := TransformToSarifFix(ctx, vuln, startLocation, endLocation)
	c.fixes[key] = cachedFix{fix: fix, err: err}
	return fix, err
}
