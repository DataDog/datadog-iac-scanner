package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "cloudfront_distribution"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cloudfront := task[variant]
	ansLib.checkState(cloudfront)

	not common_lib.valid_key(cloudfront, "logging")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cloudfront, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "cloudfront_distribution.logging should be defined",
		"keyActualValue": "cloudfront_distribution.logging is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cloudfront := task[variant]
	ansLib.checkState(cloudfront)

	not ansLib.isAnsibleTrue(cloudfront.logging.enabled)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cloudfront, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.logging.enabled", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "cloudfront_distribution.logging.enabled should be true",
		"keyActualValue": "cloudfront_distribution.logging.enabled is false",
	}
}
