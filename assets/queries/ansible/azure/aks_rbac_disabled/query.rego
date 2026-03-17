package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "azure_rm_aks"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	aks := task[variant]
	ansLib.checkState(aks)

	not common_lib.valid_key(aks, "enable_rbac")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(aks, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "azure_rm_aks.enable_rbac should be defined",
		"keyActualValue": "azure_rm_aks.enable_rbac is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	aks := task[variant]
	ansLib.checkState(aks)

	not ansLib.isAnsibleTrue(aks.enable_rbac)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(aks, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.enable_rbac", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "azure_rm_aks.enable_rbac should be set to 'yes' or 'true'",
		"keyActualValue": "azure_rm_aks.enable_rbac is not set to 'yes' or 'true'",
	}
}
