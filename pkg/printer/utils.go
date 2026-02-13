/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package printer

import (
	"context"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
)

// PrintScanDuration prints the scan duration
func PrintScanDuration(ctx context.Context, elapsed time.Duration) {
	loggerFromContext := logger.FromContext(ctx)
	elapsedStrFormat := "Scan duration: %v\n"
	loggerFromContext.Info().Msgf(elapsedStrFormat, elapsed)
}
