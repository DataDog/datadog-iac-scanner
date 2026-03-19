package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "azure_rm_mysqlserver"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	mysqlServer := task[variant]
	ansLib.checkState(mysqlServer)

	not common_lib.valid_key(mysqlServer, "enforce_ssl")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(mysqlServer, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "azure_rm_mysqlserver should have enforce_ssl set to true",
		"keyActualValue": "azure_rm_mysqlserver does not have enforce_ssl (defaults to false)",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	mysqlServer := task[variant]
	ansLib.checkState(mysqlServer)

	not ansLib.isAnsibleTrue(mysqlServer.enforce_ssl)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(mysqlServer, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.enforce_ssl", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "azure_rm_mysqlserver should have enforce_ssl set to true",
		"keyActualValue": "azure_rm_mysqlserver does has enforce_ssl set to false",
	}
}
