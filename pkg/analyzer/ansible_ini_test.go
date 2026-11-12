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
		{"ranges and ports", "[web:hosts]\nweb-[01:20].example.com:2222 ansible_user=deploy\ndb-[a:c]\n10.0.0.1:22\n", true},
		{"ipv6", "[v6]\n2001:db8::2 ansible_user=root\nfe80::\n", true},
		{"ipv6 the hosts parser rejects", "[v6]\nweb1\n2001:db8::a\n", true},
		{"children entry with extra tokens", "[web]\nweb1 ansible_host=10.0.0.1\n[prod:children]\nweb servers\n", true},
		{"children entry with a comment token", "[web]\nweb1\n[prod:children]\nweb ; production\n", true},
		{"quoted vars and comments", "[web] # front\nweb1 ansible_ssh_common_args='-o ProxyCommand=\"ssh -W %h:%p bastion\"' # c\n[prod:children]\nweb # c\n", true},
		{"pytest", "[pytest]\naddopts = -p auto\ntestpaths = tests\n", false},
		{"mypy", "[mypy]\npython_version = 3.12\nstrict = True\n", false},
		{"app config without spaces", "[dd.app.kafka]\ncluster=LocalCluster\nport=9092\n", false},
		{"pipe-delimited data", "[Header]\nFileVersion|16\nName|Value|Comment\n", false},
		{"sbt repositories", "[repositories]\nlocal\nmaven-central\nmy-ivy: https://repo.example.com/ivy/, [organization]/[module]\n", false},
		{"key value entries", "[server]\nlisten 8080\n", false},
		{"section with spaces", "[My Section]\nhost1\n", false},
		{"section of unknown type", "[tool:pytest]\nhost1\n", false},
		{"unbalanced range", "[web]\nweb-[01:20.example.com\n", false},
		{"children entry with a port", "[prod:children]\nweb:22\n", false},
		{"bracketed ipv6", "[v6]\n[2001:db8::1]:22\n", false},
		{"empty range", "[web]\nweb[]\n", false},
		{"vars without values", "[all:vars]\nansible_user\n", false},
		{"only a vars section", "[all:vars]\nansible_user=deploy\n", true},
		{"empty vars section", "[all:vars]\n", false},
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
		{"comment after the header", "[defaults] ; main\nno_log = False\nbecome_user = root\n", true},
		{"become plugin only", "[sudo_become_plugin]\nflags = -H -S -n\n", true},
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

func TestExcludedByContent(t *testing.T) {
	require.True(t, ExcludedByContent("setup.cfg", []byte("[metadata]\nname = x\n")))
	require.True(t, ExcludedByContent("pytest.ini", []byte("[pytest]\naddopts = -p auto\n")))
	require.False(t, ExcludedByContent("ansible.cfg", []byte("[defaults] ; main\nno_log = False\n")))
	require.False(t, ExcludedByContent("hosts.ini", []byte("[web]\nweb1\n")))
	require.True(t, ExcludedByContent("service.datadog.yaml", []byte("apiVersion: v3\nkind: service\nmetadata:\n  name: x\n")))
	require.False(t, ExcludedByContent("deploy.yaml", []byte("apiVersion: apps/v1\nkind: Deployment\n")))
	require.False(t, ExcludedByContent("main.tf", []byte("[metadata]\n")))
}
