package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "azure_rm_sqlserver"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	sqlserver := task[variant]

	not common_lib.valid_key(sqlserver, "ad_user")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(sqlserver, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "azure_rm_sqlserver.ad_user should be defined",
		"keyActualValue": "azure_rm_sqlserver.ad_user is undefined",
	}
}
