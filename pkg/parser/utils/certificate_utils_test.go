/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package utils

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestAddCertificateInfoDoesNotLogSourceValues(t *testing.T) {
	const secret = "synthetic-private-certificate-content"
	var logs bytes.Buffer
	ctx := zerolog.New(&logs).WithContext(t.Context())
	path := filepath.Join(t.TempDir(), "main.tf")

	require.Nil(t, AddCertificateInfo(ctx, path, secret))
	require.Contains(t, logs.String(), "Failed to get certificate")
	require.Contains(t, logs.String(), path)
	require.NotContains(t, logs.String(), secret)
}

func TestAddCertificateInfo(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join("..", "..", "..", "test", "fixtures", "test_certificate", "positive.tf")
	certificatePath := "certificate.pem"

	info := AddCertificateInfo(ctx, path, certificatePath)

	require.NotEmpty(t, info)
}

func TestGetCertificateInfo(t *testing.T) {
	filePath := filepath.Join("..", "..", "..", "test", "fixtures", "test_certificate", "certificate.pem")

	date, err := getCertificateInfo(filePath)

	require.NoError(t, err)
	require.NotEmpty(t, date)
	require.Equal(t, ".pem", filepath.Ext(filePath))
}

func TestCheckCertificateBody(t *testing.T) {
	content := "${file(certificate.pem)}"

	pem := CheckCertificate(content)

	require.NotEmpty(t, pem)
}
