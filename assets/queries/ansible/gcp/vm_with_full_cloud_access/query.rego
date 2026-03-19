package Cx

import data.generic.ansible as ansLib

canonical := "gcp_compute_instance"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	taskComputeInstance := task[variant]
	ansLib.checkState(taskComputeInstance)

	service_accounts := taskComputeInstance.service_accounts
	scopes := service_accounts[s].scopes
	lower(scopes[_]) == "cloud-platform"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(taskComputeInstance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.service_accounts", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_compute_instance.service_accounts.scopes should not contain 'cloud-platform'",
		"keyActualValue": "gcp_compute_instance.service_accounts.scopes contains 'cloud-platform'",
	}
}
