package Cx

import data.generic.ansible as ansLib

canonical := "azure_rm_rediscache"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)

	ansLib.isAnsibleTrue(instance.enable_non_ssl_port)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.enable_non_ssl_port", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "azure_rm_rediscache.enable_non_ssl_port should be set to false or undefined",
		"keyActualValue": "azure_rm_rediscache.enable_non_ssl_port is true",
	}
}
