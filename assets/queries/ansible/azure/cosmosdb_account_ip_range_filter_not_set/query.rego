package Cx

import data.generic.ansible as ansLib

canonical := "azure_rm_cosmosdbaccount"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cosmosdbaccount := task[variant]
	ansLib.checkState(cosmosdbaccount)

	not cosmosdbaccount.ip_range_filter

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cosmosdbaccount, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "'azurerm_cosmosdb_account.ip_range_filter' should be defined",
		"keyActualValue": "'azurerm_cosmosdb_account.ip_range_filter' is undefined",
	}
}
