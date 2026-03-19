package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "rds_instance"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	rds_instance := task[variant]
	ansLib.checkState(rds_instance)

	ansLib.isAnsibleFalse(rds_instance.auto_minor_version_upgrade)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(rds_instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.auto_minor_version_upgrade", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "rds_instance.auto_minor_version_upgrade should be true",
		"keyActualValue": "rds_instance.auto_minor_version_upgrade is false",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	rds_instance := task[variant]
	ansLib.checkState(rds_instance)

	not common_lib.valid_key(rds_instance, "auto_minor_version_upgrade")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(rds_instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "rds_instance.auto_minor_version_upgrade should be set",
		"keyActualValue": "rds_instance.auto_minor_version_upgrade is undefined",
	}
}
