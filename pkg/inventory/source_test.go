/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSanitizeSource(t *testing.T) {
	tests := []struct{ name, source, want string }{
		{"registry", "registry.terraform.io/terraform-aws-modules/vpc/aws", "registry.terraform.io/terraform-aws-modules/vpc/aws"},
		{"local", "infra/modules/logging", "infra/modules/logging"},
		{"ref kept", "git::https://example.invalid/acme/m.git//vpc?ref=v1.2.0", "git::https://example.invalid/acme/m.git//vpc?ref=v1.2.0"},
		{"ssh key dropped", "git::ssh://git@example.invalid/acme/m.git?ref=main&sshkey=LS0tLS1CRUdJTg", "git::ssh://git@example.invalid/acme/m.git?ref=main"},
		{"signed URL dropped", "s3::https://bucket.s3.amazonaws.com/m.zip?X-Amz-Signature=abc&X-Amz-Credential=key", "s3::https://bucket.s3.amazonaws.com/m.zip"},
		{"token dropped", "https://example.invalid/m.zip?archive=zip&token=secret", "https://example.invalid/m.zip?archive=zip"},
		{"kept as written", "git::https://example.invalid/m.git?ref=feature/x&depth=1", "git::https://example.invalid/m.git?ref=feature/x&depth=1"},
		{"unparseable query dropped", "https://example.invalid/m.zip?%zz", "https://example.invalid/m.zip"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, SanitizeSource(tt.source))
		})
	}
}
