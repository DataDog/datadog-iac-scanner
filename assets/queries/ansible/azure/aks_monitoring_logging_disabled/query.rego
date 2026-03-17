package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "azure_rm_aks"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	aks := task[variant]
	ansLib.checkState(aks)

	not common_lib.valid_key(aks, "addon")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(aks, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "azure_rm_aks.addon should be set",
		"keyActualValue": "azure_rm_aks.addon is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	aks := task[variant]
	ansLib.checkState(aks)

	not common_lib.valid_key(aks.addon, "monitoring")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(aks, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.addon", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "azure_rm_aks.addon.monitoring should be set",
		"keyActualValue": "azure_rm_aks.addon.monitoring is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	aks := task[variant]
	ansLib.checkState(aks)
	attr := {"enabled", "log_analytics_workspace_resource_id"}

	attribute := attr[j]
	not common_lib.valid_key(aks.addon.monitoring, attribute)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(aks, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.addon.monitoring", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("azure_rm_aks.addon.monitoring.%s should be set", [attr]),
		"keyActualValue": sprintf("azure_rm_aks.addon.monitoring.%s is undefined", [attr]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	aks := task[variant]
	ansLib.checkState(aks)

	not ansLib.isAnsibleTrue(aks.addon.monitoring.enabled)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(aks, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.addon.monitoring.enabled", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "azure_rm_aks.addon.monitoring.enabled should be set to 'yes' or 'false'",
		"keyActualValue": "azure_rm_aks.addon.monitoring.enabled is not set to 'yes' or 'false'",
	}
}
