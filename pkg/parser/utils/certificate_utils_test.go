/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package utils

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
)

func TestAddCertificateInfo(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join("..", "..", "..", "test", "fixtures", "test_certificate", "positive.tf")
	certificatePath := "certificate.pem"

	info := AddCertificateInfo(ctx, nil, path, certificatePath)

	require.NotEmpty(t, info)
}

func TestGetCertificateInfo(t *testing.T) {
	filePath := filepath.Join("..", "..", "..", "test", "fixtures", "test_certificate", "certificate.pem")

	date, err := getCertificateInfo(vfs.DiskFS{}, filePath)

	require.NoError(t, err)
	require.NotEmpty(t, date)
	require.Equal(t, ".pem", filepath.Ext(filePath))
}

func TestCheckCertificateBody(t *testing.T) {
	content := "${file(certificate.pem)}"

	pem := CheckCertificate(content)

	require.NotEmpty(t, pem)
}

func TestCertificateFilesystem(t *testing.T) {
	pem, err := os.ReadFile(filepath.Join("..", "..", "..", "test", "fixtures", "test_certificate", "certificate.pem"))
	require.NoError(t, err)
	for _, mode := range []string{"owned", "missing", "disk", "nil"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			certificate := filepath.Join(dir, "certificate.pem")
			host := pem
			if mode == "owned" {
				host = []byte("conflicting invalid host certificate")
			}
			require.NoError(t, os.WriteFile(certificate, host, 0600))
			var fsys vfs.FS
			switch mode {
			case "owned":
				fsys = vfs.NewMemFS(map[string][]byte{certificate: pem})
			case "missing":
				fsys = vfs.NewMemFS(nil)
			case "disk":
				fsys = vfs.DiskFS{}
			}
			for _, reference := range []string{"certificate.pem", certificate} {
				info := AddCertificateInfo(t.Context(), fsys, filepath.Join(dir, "main.yaml"), reference)
				if mode == "missing" {
					require.Nil(t, info)
				} else {
					require.NotEmpty(t, info)
					require.Equal(t, certificate, info["file"])
				}
			}
		})
	}
}
