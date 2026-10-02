/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package analyzer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLooksLikeAnsibleInventory(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{"hosts with vars", "# c\n[webservers]\nweb1 ansible_host=10.0.0.1\nweb2\n; c\n", true},
		{"ungrouped hosts", "10.0.0.1\nhost.example.com ansible_user=root\n", true},
		{"children and vars sections", "[tower]\n150.50.1.1\n[prod:children]\ntower\n[all:vars]\nadmin_password='x'\n", true},
		{"pytest", "[pytest]\naddopts = -p auto\ntestpaths = tests\n", false},
		{"mypy", "[mypy]\npython_version = 3.12\nstrict = True\n", false},
		{"app config without spaces", "[dd.app.kafka]\ncluster=LocalCluster\nport=9092\n", false},
		{"only sections", "[a]\n[b]\n", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, looksLikeAnsibleInventory([]byte(tt.content)))
		})
	}
}

func TestLooksLikeAnsibleConfig(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{"defaults", "#c\n[defaults]\ninventory = /etc/ansible/hosts\n", true},
		{"galaxy only", "[galaxy]\ncache_dir=~/.ansible/galaxy_cache\n", true},
		{"galaxy server", "[galaxy_server.release]\nurl=https://galaxy.ansible.com/\n", true},
		{"utf8 bom", "\ufeff[defaults]\nforks = 5\n", true},
		{"setup.cfg", "[metadata]\nname = x\n[options]\npackages = find:\n", false},
		{"zoo.cfg", "tickTime=2000\ndataDir=/var/zookeeper\n", false},
		{"modd.conf", "**/*.go {\n  daemon +sigterm: make run\n}\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, looksLikeAnsibleConfig([]byte(tt.content)))
		})
	}
}
