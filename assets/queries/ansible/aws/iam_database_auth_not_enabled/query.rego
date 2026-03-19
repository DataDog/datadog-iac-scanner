package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "rds_instance"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	rds_instance := task[variant]
	ansLib.checkState(rds_instance)

	common_lib.valid_for_iam_engine_and_version_check(rds_instance, "engine", "engine_version", "instance_type")
	ansLib.isAnsibleFalse(rds_instance.enable_iam_database_authentication)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(rds_instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.enable_iam_database_authentication", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "rds_instance.enable_iam_database_authentication should be enabled",
		"keyActualValue": "rds_instance.enable_iam_database_authentication is disabled",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	rds_instance := task[variant]
	ansLib.checkState(rds_instance)

	common_lib.valid_for_iam_engine_and_version_check(rds_instance, "engine", "engine_version", "instance_type")
	not common_lib.valid_key(rds_instance, "enable_iam_database_authentication")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(rds_instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "rds_instance.enable_iam_database_authentication should be defined",
		"keyActualValue": "rds_instance.enable_iam_database_authentication is undefined",
	}
}
