package Cx

import data.generic.ansible as ansLib

canonical := "iam_access_key"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	resource := task[variant]
	ansLib.checkState(resource)

	is_string(resource.user_name)
	contains(lower(resource.user_name), "root")

	object.get(resource, "active", true) == true
	object.get(resource, "state", "present") != "absent"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(resource, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "iam_access_key should not be active for a root account",
		"keyActualValue": "iam_access_key is active for a root account",
	}
}
