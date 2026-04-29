package Cx

import data.generic.common as common_lib
import data.generic.cicd as cicd_lib

# Check for hardcoded passwords in job container credentials
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"

	job := doc.jobs[j]
	container := job.container
	credentials := container.credentials

	# Check if password exists
	password := credentials.password

	# Check if password is hardcoded (not an expression)
	not contains(password, "${{")

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.container.credentials.password", [j]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Container credentials password should use secrets or expressions",
		"keyActualValue": "Container credentials contain hardcoded password",
		"searchLine": common_lib.build_search_line(["jobs", j, "container", "credentials", "password"], []),
		"resourceType": "github_action",
		"resourceName": j
	}
}

# Check for hardcoded passwords in service container credentials
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"

	job := doc.jobs[j]
	services := job.services

	# Iterate through each service
	service := services[service_name]
	credentials := service.credentials

	# Check if password exists
	password := credentials.password

	# Check if password is hardcoded (not an expression)
	not contains(password, "${{")

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.services.%s.credentials.password", [j, service_name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Service container credentials password should use secrets or expressions",
		"keyActualValue": "Service container credentials contain hardcoded password",
		"searchLine": common_lib.build_search_line(["jobs", j, "services", service_name, "credentials", "password"], []),
		"resourceType": "github_action",
		"resourceName": service_name
	}
}
