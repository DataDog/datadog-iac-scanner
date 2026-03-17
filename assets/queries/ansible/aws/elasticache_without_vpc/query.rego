package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "elasticache"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	elasticache := task[variant]
	ansLib.checkState(elasticache)

	not common_lib.valid_key(elasticache, "cache_subnet_group")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(elasticache, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'cache_subnet_group' should be defined and not null",
		"keyActualValue": "'cache_subnet_group' is undefined or null",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant], []),
	}
}
