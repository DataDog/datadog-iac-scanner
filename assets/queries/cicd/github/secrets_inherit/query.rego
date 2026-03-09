package Cx

import data.generic.common as common_lib

# Check for secrets: inherit in reusable workflow calls
CxPolicy[result] {
	doc := input.document[i]
	job := doc.jobs[j]

	# Check if this is a reusable workflow call (has 'uses' at job level)
	job.uses

	# Check if secrets is set to 'inherit'
	job.secrets == "inherit"

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.secrets={{%s}}", [j, job.secrets]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Reusable workflow should explicitly declare required secrets",
		"keyActualValue": "Reusable workflow unconditionally inherits all parent secrets",
		"searchLine": common_lib.build_search_line(["jobs", j, "secrets"], []),
		"resourceType": "github_job",
		"resourceName": j
	}
}
