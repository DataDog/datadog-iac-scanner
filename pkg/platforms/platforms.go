/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package platforms

// Canonical routing names shared by classification and filename registration.
const (
	Dockerfile = "dockerfile"
	Terraform  = "terraform"
	GRPC       = "grpc"
	Bicep      = "bicep"
)

// Supported is the list of IaC platforms with published rules available to customers.
var Supported = []string{
	"Ansible",
	"CICD",
	"CloudFormation",
	"DockerCompose",
	"Dockerfile",
	"Kubernetes",
	"Terraform",
}
