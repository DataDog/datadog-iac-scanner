package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "azure_rm_keyvault"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	keyvault := task[variant]
	ansLib.checkState(keyvault)

	ansLib.isAnsibleFalse(keyvault.enable_soft_delete)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(keyvault, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.enable_soft_delete", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "azure_rm_keyvault.enable_soft_delete should be true",
		"keyActualValue": "azure_rm_keyvault.enable_soft_delete is false",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	keyvault := task[variant]
	ansLib.checkState(keyvault)

	not common_lib.valid_key(keyvault, "enable_soft_delete")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(keyvault, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "azure_rm_keyvault.enable_soft_delete should be defined",
		"keyActualValue": "azure_rm_keyvault.enable_soft_delete is undefined",
	}
}
