/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfmodules

import (
	"net"
	"strings"

	svchost "github.com/hashicorp/terraform-svchost"
	tfaddr "github.com/opentofu/registry-address"
)

const terraformRegistryHost = svchost.Hostname("registry.terraform.io")

// RegistryModuleSource is a Terraform registry module address.
type RegistryModuleSource struct {
	Host      string
	Namespace string
	Name      string
	Provider  string
	Subdir    string
}

// ParseRegistryModuleSource parses a registry module source, including hosts
// with ports and //subdir selections. Implicit three-part addresses use
// registry.terraform.io rather than the OpenTofu default host.
func ParseRegistryModuleSource(source string) (RegistryModuleSource, error) {
	addr, err := tfaddr.ParseModuleSource(strings.TrimSpace(source))
	if err != nil {
		return RegistryModuleSource{}, err
	}
	if addr.Package.Host == tfaddr.DefaultModuleRegistryHost {
		addr.Package.Host = terraformRegistryHost
	}
	return RegistryModuleSource{
		Host:      addr.Package.Host.ForDisplay(),
		Namespace: addr.Package.Namespace,
		Name:      addr.Package.Name,
		Provider:  addr.Package.TargetSystem,
		Subdir:    addr.Subdir,
	}, nil
}

func (s *RegistryModuleSource) Public() bool {
	host := s.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.EqualFold(host, string(terraformRegistryHost))
}

func (s *RegistryModuleSource) String() string {
	src := s.Host + "/" + s.Namespace + "/" + s.Name + "/" + s.Provider
	if s.Subdir != "" {
		src += "//" + s.Subdir
	}
	return src
}
