package resolver

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDescribeModuleSource(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		version string
		want    SourceDescriptor
	}{
		{
			name:    "public registry subdirectory",
			source:  "terraform-aws-modules/vpc/aws//modules/vpc-endpoints",
			version: "~> 5.0",
			want: SourceDescriptor{
				NormalizedSource: "registry.terraform.io/terraform-aws-modules/vpc/aws",
				SourceType:       "registry",
				SourceCategory:   "public_registry",
				RegistryScope:    "public",
				RequestedVersion: "~> 5.0",
				Subdirectory:     "modules/vpc-endpoints",
			},
		},
		{
			name:   "private registry",
			source: "registry.example.com/acme/network/aws",
			want: SourceDescriptor{
				NormalizedSource: "registry.example.com/acme/network/aws",
				SourceType:       "registry",
				SourceCategory:   "private_registry",
				RegistryScope:    "private",
			},
		},
		{
			name:   "git ref and subdirectory",
			source: "git::https://github.com/acme/network.git//modules/vpc?ref=v1.2.3",
			want: SourceDescriptor{
				NormalizedSource: "github.com/acme/network",
				SourceType:       "git",
				SourceCategory:   "git",
				RequestedRef:     "v1.2.3",
				Subdirectory:     "modules/vpc",
			},
		},
		{
			name:   "object storage",
			source: "s3::https://s3.amazonaws.com/example/module.zip",
			want: SourceDescriptor{
				NormalizedSource: "https://s3.amazonaws.com/example/module.zip",
				SourceType:       "s3",
				SourceCategory:   "s3",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, DescribeModuleSource(test.source, test.version))
		})
	}
}
