/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package platforms

// Supported is the list of IaC platforms accepted by the scanner.
// Catalog visibility for default rules is controlled separately via is_published.
var Supported = []string{
	"Ansible",
	"CICD",
	"CloudFormation",
	"DockerCompose",
	"Dockerfile",
	"Kubernetes",
	"Terraform",
}
