package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "s3_cors"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cors := task[variant]
	ansLib.checkState(cors)

	rule := cors.rules[c]
	common_lib.unsecured_cors_rule(rule.allowed_methods, rule.allowed_headers, rule.allowed_origins)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cors, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.rules", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s[%d] should not allow all methods, all headers or several origins", [variant, c]),
		"keyActualValue": sprintf("%s[%d] allows all methods, all headers or several origins", [variant, c]),
	}
}
