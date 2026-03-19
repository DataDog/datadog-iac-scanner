package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "cloudfront_distribution"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cloudfront_distribution := task[variant]

	ansLib.checkState(cloudfront_distribution)
	not common_lib.valid_key(cloudfront_distribution, "enabled")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cloudfront_distribution, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"searchValue": "enabled",
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("name={{%s}}.{{%s}}.enabled should be set to 'true'", [task.name, variant]),
		"keyActualValue": sprintf("name={{%s}}.{{%s}}.enabled is not set", [task.name, variant]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant], []),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cloudfront_distribution := task[variant]

	ansLib.checkState(cloudfront_distribution)
	ansLib.isAnsibleFalse(cloudfront_distribution.enabled)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cloudfront_distribution, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.enabled", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("name={{%s}}.{{%s}}.enabled should be set to 'true'", [task.name, variant]),
		"keyActualValue": sprintf("name={{%s}}.{{%s}}.enabled is set to '%s'", [task.name, variant, cloudfront_distribution.enabled]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant], ["enabled"]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cloudfront_distribution := task[variant]

	ansLib.checkState(cloudfront_distribution)
	not common_lib.valid_key(cloudfront_distribution, "origins")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cloudfront_distribution, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"searchValue": "origins",
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("name={{%s}}.{{%s}}.origins should be defined", [task.name, variant]),
		"keyActualValue": sprintf("name={{%s}}.{{%s}}.origins is not defined", [task.name, variant]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant], []),
	}
}
