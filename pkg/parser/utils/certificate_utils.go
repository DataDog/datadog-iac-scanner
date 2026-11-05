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
	"os"
	"path/filepath"
	"regexp"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
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

func getCertificateInfo(filePath string) (certInfo, error) {
	certPEM, err := os.ReadFile(filepath.Clean(filePath))

	if err != nil {
		return certInfo{}, err
	}
	return parseCertificate(certPEM)
}

func parseCertificate(certPEM []byte) (certInfo, error) {
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

	rsaBytes := -1
	if key, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		rsaBytes = key.Size()
	}

	return certInfo{date: certDate, rsaKeyBytes: rsaBytes}, nil
}

func (c certInfo) attributes() map[string]interface{} {
	attributes := map[string]interface{}{"expiration_date": c.date}
	if c.rsaKeyBytes != -1 {
		attributes["rsa_key_bytes"] = c.rsaKeyBytes
	}
	return attributes
}

// CertificateInfo is what a scan reads of a PEM certificate: its expiration
// date, [year, month, day], and, for an RSA key, rsa_key_bytes, the key's size
// in bytes. ok is false when certPEM is not a certificate.
func CertificateInfo(certPEM string) (info map[string]interface{}, ok bool) {
	c, err := parseCertificate([]byte(certPEM))
	if err != nil {
		return nil, false
	}
	return c.attributes(), true
}

// certificateFile is the path of the certificate file content names, a full
// path or one relative to the directory of the file at path.
func certificateFile(ctx context.Context, path, content string) string {
	if _, err := os.Stat(content); err == nil {
		return content
	}
	contextLogger := logger.FromContext(ctx)
	contextLogger.Trace().Msgf("path to the certificate content is not a valid: %s", content)
	return filepath.Join(filepath.Dir(path), content)
}

// CertificateFileInfo is CertificateInfo for the certificate file content
// names (see certificateFile), nil when it cannot be read.
func CertificateFileInfo(ctx context.Context, path, content string) map[string]interface{} {
	return fileInfo(ctx, certificateFile(ctx, path, content))
}

func fileInfo(ctx context.Context, filePath string) map[string]interface{} {
	c, err := getCertificateInfo(filePath)
	if err != nil {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Error().Msgf("Failed to get certificate path %s: %s", filePath, err)
		return nil
	}
	return c.attributes()
}

// AddCertificateInfo gets and adds certificate information of a certificate file
func AddCertificateInfo(ctx context.Context, path, content string) map[string]interface{} {
	filePath := certificateFile(ctx, path, content)
	attributes := fileInfo(ctx, filePath)
	if attributes != nil {
		attributes["file"] = filePath
	}
	return attributes
}
