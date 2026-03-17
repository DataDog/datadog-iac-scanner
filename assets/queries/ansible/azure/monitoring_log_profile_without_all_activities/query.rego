package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "azure_rm_monitorlogprofile"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	azureMonitor := task[variant]
	ansLib.checkState(azureMonitor)
	categories := azureMonitor.categories
	elem := ["write", "action", "delete"][_]

	not common_lib.inArray([c | c := lower(categories[_])], elem)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(azureMonitor, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.categories", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "azure_rm_monitorlogprofile.categories should have all categories, Write, Action and Delete",
		"keyActualValue": "azure_rm_monitorlogprofile.categories does not have all categories, Write, Action and Delete",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	azureMonitor := task[variant]
	ansLib.checkState(azureMonitor)

	not common_lib.valid_key(azureMonitor, "categories")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(azureMonitor, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "azure_rm_monitorlogprofile.categories should be defined",
		"keyActualValue": "azure_rm_monitorlogprofile.categories is undefined",
	}
}
