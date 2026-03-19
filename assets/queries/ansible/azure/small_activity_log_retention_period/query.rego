package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "azure_rm_monitorlogprofile"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	azureMonitor := task[variant]
	ansLib.checkState(azureMonitor)

	not ansLib.isAnsibleTrue(azureMonitor.retention_policy.enabled)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(azureMonitor, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.retention_policy.enabled", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "azure_rm_monitorlogprofile.retention_policy.enabled should be true or yes",
		"keyActualValue": "azure_rm_monitorlogprofile.retention_policy.enabled is false or no",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	azureMonitor := task[variant]
	ansLib.checkState(azureMonitor)
	retentionPolicy := azureMonitor.retention_policy

	ansLib.isAnsibleTrue(retentionPolicy.enabled)
	common_lib.between(retentionPolicy.days, 1, 364)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(azureMonitor, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.retention_policy.days", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "azure_rm_monitorlogprofile.retention_policy.days should be greater than or equal to 365 days or 0 (indefinitely)",
		"keyActualValue": "azure_rm_monitorlogprofile.retention_policy.days is less than 365 days or different than 0 (indefinitely)",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	azureMonitor := task[variant]
	ansLib.checkState(azureMonitor)

	not common_lib.valid_key(azureMonitor, "retention_policy")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(azureMonitor, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "azure_rm_monitorlogprofile.retention_policy should be defined",
		"keyActualValue": "azure_rm_monitorlogprofile.retention_policy is undefined",
	}
}
