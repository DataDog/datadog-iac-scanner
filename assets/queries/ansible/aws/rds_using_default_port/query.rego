package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "rds_instance"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)

	enginePort := common_lib.engines[e]

	instance.engine == e
	instance.port == enginePort

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.port", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'port' should not be set to %d", [enginePort]),
		"keyActualValue": sprintf("'port' is set to %d", [enginePort]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "port"], []),
	}
}
