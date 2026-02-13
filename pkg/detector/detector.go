/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/rs/zerolog"
)

type kindDetectLine interface {
	DetectLine(ctx context.Context, file *model.FileMetadata, searchKey string, outputLines int) model.VulnerabilityLines
}

// DetectLine is a struct that associates a kindDetectLine to its FileKind
type DetectLine struct {
	detectors       map[model.FileKind]kindDetectLine
	outputLines     int
	logWithFields   *zerolog.Logger
	defaultDetector kindDetectLine
}

// NewDetectLine creates a new DetectLine's reference
func NewDetectLine(outputLines int) *DetectLine {
	return &DetectLine{
		detectors:       make(map[model.FileKind]kindDetectLine),
		logWithFields:   &zerolog.Logger{},
		outputLines:     outputLines,
		defaultDetector: defaultDetectLine{},
	}
}

// SetupLogs will change the logger feild to be used in kindDetectLine DetectLine method
func (d *DetectLine) SetupLogs(logger *zerolog.Logger) {
	d.logWithFields = logger
}

// Add adds a new kindDetectLine to the caller and returns it
func (d *DetectLine) Add(detector kindDetectLine, kind model.FileKind) *DetectLine {
	d.detectors[kind] = detector
	return d
}

// DetectLine will use the correct kindDetectLine according to the files kind
// if file kind is not in detectors default detect line is called
func (d *DetectLine) DetectLine(ctx context.Context, file *model.FileMetadata, searchKey string) model.VulnerabilityLines {
	if det, ok := d.detectors[file.Kind]; ok {
		return det.DetectLine(ctx, file, searchKey, d.outputLines)
	}
	return d.defaultDetector.DetectLine(ctx, file, searchKey, d.outputLines)
}
