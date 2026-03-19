package Cx

import data.generic.ansible as ansLib

canonical := "azure_rm_storageaccount"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	storageaccount := task[variant]
	ansLib.checkState(storageaccount)

	lower(storageaccount.network_acls.default_action) == "deny"
	not containsAzureService(storageaccount.network_acls.bypass)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(storageaccount, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.network_acls.bypass", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "azure_rm_storageaccount.network_acls.bypass should not be set or contain 'AzureServices'",
		"keyActualValue": "azure_rm_storageaccount.network_acls.bypass does not contain 'AzureServices' ",
	}
}

containsAzureService(bypass) {
	bypass == "\"\""
}

containsAzureService(bypass) {
	values := split(bypass, ",")
	values[j] == "AzureServices"
}
