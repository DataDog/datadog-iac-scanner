package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "elasticache"

engines := {"memcached": 11211, "redis": 6379}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	elasticache := task[variant]
	ansLib.checkState(elasticache)

	enginePort := engines[e]
	elasticache.engine == e
	elasticache.cache_port == enginePort

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(elasticache, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.cache_port", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'cache_port' should not be set to %d", [enginePort]),
		"keyActualValue": sprintf("'cache_port' is set to %d", [enginePort]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "cache_port"], []),
	}
}
