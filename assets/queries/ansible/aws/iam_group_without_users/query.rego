package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "iam_group"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	iam_group := task[variant]
	ansLib.checkState(iam_group)

	not common_lib.valid_key(iam_group, "users")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(iam_group, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("%s.users should be defined and not null", [variant]),
		"keyActualValue": sprintf("%s.users is undefined or null", [variant]),
	}
}
