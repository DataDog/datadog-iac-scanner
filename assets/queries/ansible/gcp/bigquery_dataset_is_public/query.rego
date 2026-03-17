package Cx

import data.generic.ansible as ansLib

canonical := "gcp_bigquery_dataset"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	bigquery_dataset := task[variant]
	ansLib.checkState(bigquery_dataset)

	access := bigquery_dataset.access
	lower(access[_].special_group) == "allauthenticatedusers"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(bigquery_dataset, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.access", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_bigquery_dataset.access.special_group should not equal to 'allAuthenticatedUsers'",
		"keyActualValue": "gcp_bigquery_dataset.access.special_group is equal to 'allAuthenticatedUsers'",
	}
}
