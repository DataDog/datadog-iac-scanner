package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "lambda"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	lambda := task[variant]

	ansLib.checkState(lambda)
	not common_lib.valid_key(lambda, "tags")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(lambda, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("name={{%s}}.{{%s}}.tags should be defined", [task.name, variant]),
		"keyActualValue": sprintf("name={{%s}}.{{%s}}.tags is undefined", [task.name, variant]),
	}
}
