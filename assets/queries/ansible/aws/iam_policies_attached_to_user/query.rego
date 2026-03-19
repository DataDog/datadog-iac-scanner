package Cx

import data.generic.ansible as ansLib

canonical := "iam_policy"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	iamPolicy := task[variant]
	ansLib.checkState(iamPolicy)

	lower(iamPolicy.iam_type) == "user"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(iamPolicy, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.iam_type", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "iam_policy.iam_type should be configured with group or role",
		"keyActualValue": "iam_policy.iam_type is configured with user",
	}
}
