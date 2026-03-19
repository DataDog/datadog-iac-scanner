package Cx

import data.generic.ansible as ansLib

canonical := "azure_rm_containerregistry"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	containerReg := task[variant]
	ansLib.checkState(containerReg)

	ansLib.isAnsibleTrue(containerReg.admin_user_enabled)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(containerReg, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.admin_user_enabled", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "azure_rm_containerregistry.admin_user_enabled should be false or undefined (defaults to false)",
		"keyActualValue": "azure_rm_containerregistry.admin_user_enabled is true",
	}
}
