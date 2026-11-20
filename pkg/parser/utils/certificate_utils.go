/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package utils

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"path/filepath"
	"regexp"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
)

type certInfo struct {
	date        [3]int
	rsaKeyBytes int
}

// CheckCertificate verifies if the attribute 'certificate_body' refers a file
func CheckCertificate(content string) string {
	var re = regexp.MustCompile(`[0-9a-zA-Z-/\\_.]+\.pem`)

	match := re.FindString(content)

	return match
}

func getCertificateInfo(fsys vfs.FS, filePath string) (certInfo, error) {
	certPEM, err := fsys.ReadFile(filepath.Clean(filePath))

	if err != nil {
		return certInfo{}, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return certInfo{}, errors.New("failed to parse the certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return certInfo{}, err
	}

	var certDate [3]int
	certDate[0] = cert.NotAfter.Year()
	certDate[1] = int(cert.NotAfter.Month())
	certDate[2] = cert.NotAfter.Day()

	var rsaBytes int

	switch t := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		_ = t
		rsaBytes = cert.PublicKey.(*rsa.PublicKey).Size()
	default:
		rsaBytes = -1
	}

	return certInfo{date: certDate, rsaKeyBytes: rsaBytes}, nil
}

// AddCertificateInfo gets and adds certificate information using the supplied
// non-nil filesystem. Parser entry points own filesystem defaulting.
func AddCertificateInfo(ctx context.Context, fsys vfs.FS, path, content string) map[string]interface{} {
	loggerFromContext := logger.FromContext(ctx)
	filePath := content
	if !filepath.IsAbs(content) {
		if _, err := fsys.Stat(content); err != nil {
			loggerFromContext.Trace().Msgf("certificate reference is relative to its input file: %s", content)
			filePath = filepath.Join(filepath.Dir(path), content)
		}
	}

	date, err := getCertificateInfo(fsys, filePath)

	if err == nil {
		attributes := make(map[string]interface{})
		attributes["file"] = filePath
		attributes["expiration_date"] = date.date

		if date.rsaKeyBytes != -1 {
			attributes["rsa_key_bytes"] = date.rsaKeyBytes
		}

		return attributes
	}

	loggerFromContext.Error().Msgf("Failed to get certificate path %s: %s", filePath, err)

	return nil
}
