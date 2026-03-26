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
	"regexp"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	vault "github.com/sosedoff/ansible-vault-go"
)

var ansibleVaultHeaderPattern = regexp.MustCompile(`^\s*\$ANSIBLE_VAULT`)

// DecryptAnsibleVault verifies if the fileContent is encrypted by ansible-vault. If yes, the function decrypts it
func DecryptAnsibleVault(ctx context.Context, fileContent []byte, secret string) []byte {
	contextLogger := logger.FromContext(ctx)
	if secret != "" && IsAnsibleVaultEncrypted(fileContent) {
		content, err := vault.Decrypt(string(fileContent), secret)
		if err == nil {
			contextLogger.Info().Msg("Decrypting Ansible Vault file")
			fileContent = []byte(content)
		} else {
			contextLogger.Debug().Msgf("failed to decrypt Ansible Vault content: %s", err)
		}
	}
	return fileContent
}

var (
	vaultPasswordOnce   sync.Once
	cachedVaultPassword string
)

// GetVaultPassword returns the vault password read from ANSIBLE_VAULT_PASSWORD_FILE, cached after the first call.
func GetVaultPassword() string {
	vaultPasswordOnce.Do(func() {
		cachedVaultPassword = ReadVaultPassword(os.Getenv("ANSIBLE_VAULT_PASSWORD_FILE"))
	})
	return cachedVaultPassword
}

// IsAnsibleVaultEncrypted reports whether content is Ansible Vault encrypted.
func IsAnsibleVaultEncrypted(content []byte) bool {
	return ansibleVaultHeaderPattern.Match(content)
}

// ReadVaultPassword reads the vault password from the file at filePath.
func ReadVaultPassword(filePath string) string {
	if filePath == "" {
		return ""
	}
	data, err := os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
