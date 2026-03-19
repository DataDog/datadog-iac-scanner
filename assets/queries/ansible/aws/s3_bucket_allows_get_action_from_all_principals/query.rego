package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "s3_bucket"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	bucket := task[variant]
	ansLib.checkState(bucket)

	st := common_lib.get_statement(common_lib.get_policy(bucket.policy))
	statement := st[_]

	common_lib.is_allow_effect(statement)

	common_lib.containsOrInArrayContains(statement.Action, "get")
	statement.Principal == "*"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(bucket, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.policy", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("s3_bucket[%s] should not allow Get Action From All Principals", [bucket.name]),
		"keyActualValue": sprintf("s3_bucket[%s] allows Get Action From All Principals", [bucket.name]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "policy"], []),
	}
}
