package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "route53"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	route53 := task[variant]
	ansLib.checkState(route53)

	not common_lib.valid_key(route53, "value")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(route53, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "route53.value should be defined or not null",
		"keyActualValue": "route53.value is undefined or null",
	}
}
