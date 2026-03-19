package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "kms_key"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	aws_kms := task[variant]
	ansLib.checkState(aws_kms)

	st := common_lib.get_statement(common_lib.get_policy(aws_kms.policy))
	statement := st[_]

	common_lib.is_allow_effect(statement)
	not common_lib.valid_key(statement, "Condition")
	common_lib.has_wildcard(statement, "kms:*")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(aws_kms, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.policy", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "aws_kms.policy should not have wildcard in 'Action' and 'Principal'",
		"keyActualValue": "aws_kms.policy has wildcard in 'Action' or 'Principal'",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "policy"], []),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	aws_kms := task[variant]
	ansLib.checkState(aws_kms)

	not common_lib.valid_key(aws_kms, "policy")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(aws_kms, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "'policy' should be undefined or null",
		"keyActualValue": "'policy' is defined and not null",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant], []),
	}
}
