package Cx

import data.generic.common as common_lib
import data.generic.cicd as cicd_lib

# Check for unpinned container images in job container key
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	job := doc.jobs[j]
	container := job.container

	not object.get(container, "image", false)

	# Check if image is not pinned to a digest (no @sha256:)
	not contains(container, "@sha256:")

	# Also check if it's not an expression (expressions might be pinned dynamically)
	not contains(container, "${{")

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.container={{%s}}", [j, container]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Container image should be pinned to a specific digest",
		"keyActualValue": sprintf("Container image '%s' is not pinned to a digest", [container]),
		"searchLine": common_lib.build_search_line(["jobs", j, "container"], []),
		"resourceType": "github_action",
		"resourceName": j
	}
}

# Check for unpinned container images in job container
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
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
		"resourceType": "github_action",
		"resourceName": j
	}
}

# Check for unpinned service container images
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
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
		"resourceType": "github_action",
		"resourceName": service_name
	}
}

# Check for expression-based container images
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	job := doc.jobs[j]
	container := job.container

	not contains(container.image, "@sha256:")
	check_unpinned_expression(job, container)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.container.image={{%s}}", [j, container.image]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Container image should be statically pinned to a specific digest",
		"keyActualValue": "Container image uses an expression which may not be pinned to a digest",
		"searchLine": common_lib.build_search_line(["jobs", j, "container", "image"], []),
		"resourceType": "github_action",
		"resourceName": j
	}
}

# Check for expression-based service container images
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	job := doc.jobs[j]
	services := job.services

	service := services[service_name]

	not contains(service.image, "@sha256:")
	check_unpinned_expression(job, service)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.services.%s.image={{%s}}", [j, service_name, service.image]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Service container image should be statically pinned to a specific digest",
		"keyActualValue": "Service container image uses an expression which may not be pinned to a digest",
		"searchLine": common_lib.build_search_line(["jobs", j, "services", service_name, "image"], []),
		"resourceType": "github_action",
		"resourceName": service_name
	}
}

# Helper function to check if job has no pinned images in matrix
no_pinned_in_matrix(job, fields) {
	matrix_values := [value | value := job.strategy.matrix[fields[_]]]
	pinned_values := [matrix_value | walk(matrix_values, [_, matrix_value]); contains(matrix_value, "@sha256:")]
	count(pinned_values) == 0
}

# Helper function to check if job has unpinned images in matrix
# Should only return true if field has a pinned sha and not all are pinned
not_all_pinned(job, field) {
	matrix_value := job.strategy.matrix[field]
	pinned_values := count([v | v := matrix_value[_]; contains(v, "@sha256:")])
	pinned_values > 0
	pinned_values != count(matrix_value)
}

# Case 1: Expression references matrix but matrix has no pinned images
# Case 1.1: Expression references matrix and no pinned image within expression
check_unpinned_expression(job, container_or_service) {
	parsed_exprs := container_or_service._parsed_expressions_image[_]
	parsed_exprs.parse_ok == true

	# Check if expression references matrix
	contains(parsed_exprs.raw, "matrix.")

	matrix := regex.find_n("matrix\\.[a-zA-Z0-9_]+", parsed_exprs.raw, -1)
	fields := [field | field := split(matrix[_], ".")[1]]

	# Look for pinned images in strategy.matrix values
	no_pinned_in_matrix(job, fields)
} 
# Case 1.2: Expression references matrix and field with pinned image has unpinneds
else {
	parsed_exprs := container_or_service._parsed_expressions_image[_]
	parsed_exprs.parse_ok == true

	# Check if expression references matrix
	contains(parsed_exprs.raw, "matrix.")

	matrix := regex.find_n("matrix\\.[a-zA-Z0-9_]+", parsed_exprs.raw, -1)[_]
	field := split(matrix, ".")[1]

	# There is a pinned expression, if it's a string all good
	# Issues might happen when it's an array that may not have all 
	is_array(job.strategy.matrix[field])

	# Look for pinned images in strategy.matrix values
	not_all_pinned(job, field)
}
# Case 2: Expression doesn't reference matrix
else {
	parsed_exprs := container_or_service._parsed_expressions_image[_]
	parsed_exprs.parse_ok == true

	# Expression exists but doesn't reference matrix
	not contains(parsed_exprs.raw, "matrix.")
}
