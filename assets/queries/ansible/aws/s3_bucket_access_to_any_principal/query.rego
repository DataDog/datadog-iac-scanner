package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "s3_bucket"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	s3_bucket := task[variant]
	ansLib.checkState(s3_bucket)

	st := common_lib.get_statement(common_lib.get_policy(s3_bucket.policy))
	statement := st[_]

	common_lib.is_allow_effect(statement)
	statement.Principal == "*"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(s3_bucket, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.policy", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "s3_bucket.policy.Statement shouldn't make the bucket accessible to all AWS Accounts",
		"keyActualValue": "s3_bucket.policy.Statement does make the bucket accessible to all AWS Accounts",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "policy"], []),
	}
}
