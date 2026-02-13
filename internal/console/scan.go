/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package console

import (
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/scan"
	"github.com/rs/zerolog/log"
)

func ExecuteScan(ctx context.Context, scanParams *scan.Parameters) (scan.ScanMetadata, error) {
	log.Debug().Msg("console.scan()")

	console := newConsole()

	console.preScan(scanParams)

	client, err := scan.NewClient(ctx, scanParams, console.Printer)

	if err != nil {
		log.Err(err).Msgf("failed to create scan client%v", err)
		return scan.ScanMetadata{}, err
	}

	scanMetadata, err := client.PerformScan(ctx)

	if err != nil {
		log.Err(err).Msgf("failed to perform scan: %v", err)
		return scan.ScanMetadata{}, err
	}

	return scanMetadata, nil
}
