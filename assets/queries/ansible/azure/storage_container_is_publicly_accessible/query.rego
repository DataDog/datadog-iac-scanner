package Cx

import data.generic.ansible as ansLib

canonical := "azure_rm_storageblob"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	storageblob := task[variant]
	ansLib.checkState(storageblob)

	hasPublicAccess(lower(storageblob.public_access))

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(storageblob, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.public_access", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "azure_rm_storageblob.public_access should not be set",
		"keyActualValue": "azure_rm_storageblob.public_access is equal to 'blob' or 'container'",
	}
}

hasPublicAccess("blob") = true

hasPublicAccess("container") = true
