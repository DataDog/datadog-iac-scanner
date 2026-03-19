package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "azure_rm_cosmosdbaccount"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cosmosdbaccount := task[variant]
	ansLib.checkState(cosmosdbaccount)

	not common_lib.valid_key(cosmosdbaccount, "tags")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cosmosdbaccount, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.tags", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "azure_rm_cosmosdbaccount.tags should be defined",
		"keyActualValue": "azure_rm_cosmosdbaccount.tags is undefined",
	}
}
