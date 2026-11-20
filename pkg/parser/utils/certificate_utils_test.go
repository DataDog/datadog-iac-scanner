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

	info := AddCertificateInfo(ctx, vfs.DiskFS{}, path, certificatePath)

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
	pem, err := os.ReadFile(filepath.Join("..", "..", "..", "test", "fixtures", "test_certificate", "certificate.pem"))
	require.NoError(t, err)
	for _, test := range []struct {
		name, content, reference string
	}{
		{"file expression", "${file(certificate.pem)}", "certificate.pem"},
		{"inline certificate", string(pem), ""},
		{"unrelated string", "no certificate reference", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.reference, CheckCertificate(test.content))
		})
	}
}

func TestCertificateFilesystem(t *testing.T) {
	pem, err := os.ReadFile(filepath.Join("..", "..", "..", "test", "fixtures", "test_certificate", "certificate.pem"))
	require.NoError(t, err)
	dir := t.TempDir()
	certificate := filepath.Join(dir, "certificate.pem")
	for _, test := range []struct {
		name      string
		hostBytes []byte
		fsys      vfs.FS
		reference string
		wantCert  bool
	}{
		{"owned relative", []byte("conflicting invalid host certificate"), vfs.NewMemFS(map[string][]byte{certificate: pem}), "certificate.pem", true},
		{"owned absolute", []byte("conflicting invalid host certificate"), vfs.NewMemFS(map[string][]byte{certificate: pem}), certificate, true},
		{"missing relative", pem, vfs.NewMemFS(nil), "certificate.pem", false},
		{"missing absolute", pem, vfs.NewMemFS(nil), certificate, false},
		{"disk relative", pem, vfs.DiskFS{}, "certificate.pem", true},
		{"disk absolute", pem, vfs.DiskFS{}, certificate, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.NoError(t, os.WriteFile(certificate, test.hostBytes, 0600))
			info := AddCertificateInfo(t.Context(), test.fsys, filepath.Join(dir, "main.yaml"), test.reference)
			if test.wantCert {
				require.Equal(t, certificate, info["file"])
				require.Equal(t, [3]int{2022, 3, 27}, info["expiration_date"])
				require.Equal(t, 512, info["rsa_key_bytes"])
			} else {
				require.Nil(t, info)
				fsys := test.fsys.(*vfs.MemFS)
				require.Equal(t, []string{filepath.ToSlash(certificate)}, fsys.MissingFiles())
			}
		})
	}
}
