package Cx

import data.generic.common as common_lib

# Check for unpinned container images in job container
CxPolicy[result] {
	doc := input.document[i]
	job := doc.jobs[j]
	container := job.container

	# Check if container has an image
	image := container.image

	# Check if image is not pinned to a digest (no @sha256:)
	not contains(image, "@sha256:")

	# Also check if it's not an expression (expressions might be pinned dynamically)
	not contains(image, "${{")

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.container.image={{%s}}", [j, image]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Container image should be pinned to a specific digest",
		"keyActualValue": sprintf("Container image '%s' is not pinned to a digest", [image]),
		"searchLine": common_lib.build_search_line(["jobs", j, "container", "image"], []),
		"resourceType": "github_job",
		"resourceName": j
	}
}

# Check for unpinned service container images
CxPolicy[result] {
	doc := input.document[i]
	job := doc.jobs[j]
	services := job.services

	# Iterate through each service
	service := services[service_name]
	image := service.image

	# Check if image is not pinned to a digest
	not contains(image, "@sha256:")

	# Also check if it's not an expression
	not contains(image, "${{")

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.services.%s.image={{%s}}", [j, service_name, image]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Service container image should be pinned to a specific digest",
		"keyActualValue": sprintf("Service container image '%s' is not pinned to a digest", [image]),
		"searchLine": common_lib.build_search_line(["jobs", j, "services", service_name, "image"], []),
		"resourceType": "github_service",
		"resourceName": service_name
	}
}

# Check for expression-based container images
CxPolicy[result] {
	doc := input.document[i]
	job := doc.jobs[j]
	container := job.container

	check_unpinned_expression(job, container)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.container.image={{%s}}", [j, container.image]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Container image should be statically pinned to a specific digest",
		"keyActualValue": "Container image uses an expression which may not be pinned to a digest",
		"searchLine": common_lib.build_search_line(["jobs", j, "container", "image"], []),
		"resourceType": "github_job",
		"resourceName": j
	}
}

# Check for expression-based service container images
CxPolicy[result] {
	doc := input.document[i]
	job := doc.jobs[j]
	services := job.services

	service := services[service_name]

	check_unpinned_expression(job, service)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.services.%s.image={{%s}}", [j, service_name, service.image]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Service container image should be statically pinned to a specific digest",
		"keyActualValue": "Service container image uses an expression which may not be pinned to a digest",
		"searchLine": common_lib.build_search_line(["jobs", j, "services", service_name, "image"], []),
		"resourceType": "github_service",
		"resourceName": service_name
	}
}

# Helper function to check if job has pinned images in matrix
has_pinned_in_matrix(job) {
	job.strategy
	job.strategy.matrix
	matrix_value := job.strategy.matrix[_]
	is_string(matrix_value)
	contains(matrix_value, "@sha256:")
} else {
	job.strategy
	job.strategy.matrix
	matrix_value := job.strategy.matrix[_]
	is_array(matrix_value)
	matrix_value[_]
	contains(matrix_value[_], "@sha256:")
}

# Case 1: Expression references matrix but matrix has no pinned images
check_unpinned_expression(job, container_or_service) {
	parsed_exprs := container_or_service._parsed_expressions_image[_]
	parsed_exprs.parse_ok == true

	# Check if expression references matrix
	contains(parsed_exprs.raw, "matrix.")

	# Look for pinned images in strategy.matrix values
	not has_pinned_in_matrix(job)
}

# Case 2: Expression doesn't reference matrix
check_unpinned_expression(job, container_or_service) {
	parsed_exprs := container_or_service._parsed_expressions_image[_]
	parsed_exprs.parse_ok == true

	# Expression exists but doesn't reference matrix
	not contains(parsed_exprs.raw, "matrix.")
}
