package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "azure_rm_storageaccount"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	storage := task[variant]
	ansLib.checkState(storage)

	not common_lib.valid_key(storage, "minimum_tls_version")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(storage, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "azure_rm_storageaccount.minimum_tls_version should be defined",
		"keyActualValue": "azure_rm_storageaccount.minimum_tls_version is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	storage := task[variant]
	ansLib.checkState(storage)

	storage.minimum_tls_version != "TLS1_2"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(storage, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.minimum_tls_version", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "azure_rm_storageaccount should be using the latest version of TLS encryption",
		"keyActualValue": sprintf("azure_rm_storageaccount is using version %s of TLS encryption", [storage.minimum_tls_version]),
	}
}
