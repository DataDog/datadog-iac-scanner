package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "cloudtrail"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cloudtrail := task[variant]
	ansLib.checkState(cloudtrail)

	common_lib.valid_key(cloudtrail, "is_multi_region_trail")
	ansLib.isAnsibleFalse(cloudtrail.is_multi_region_trail)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cloudtrail, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.is_multi_region_trail", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "cloudtrail.is_multi_region_trail should be true",
		"keyActualValue": "cloudtrail.is_multi_region_trail is false",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cloudtrail := task[variant]
	ansLib.checkState(cloudtrail)

	not common_lib.valid_key(cloudtrail, "is_multi_region_trail")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cloudtrail, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "cloudtrail.is_multi_region_trail should be defined and set to true",
		"keyActualValue": "cloudtrail.is_multi_region_trail is undefined",
	}
}
