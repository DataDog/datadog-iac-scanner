package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "cloudformation"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cloudformation := task[variant]
	ansLib.checkState(cloudformation)

	not common_lib.valid_key(cloudformation, "stack_policy")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cloudformation, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "cloudformation.stack_policy should be set",
		"keyActualValue": "cloudformation.stack_policy is undefined",
	}
}
