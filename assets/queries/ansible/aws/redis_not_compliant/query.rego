package Cx

import data.generic.ansible as ansLib

canonical := "elasticache"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	min_version_string = "4.0.10"
	elasticache := task[variant]
	ansLib.checkState(elasticache)

	eval_version_number(elasticache.cache_engine_version) < eval_version_number(min_version_string)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(elasticache, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.cache_engine_version", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "elasticache.cache_engine_version should be compliant with the AWS PCI DSS requirements",
		"keyActualValue": "elasticache.cache_engine_version isn't compliant with the AWS PCI DSS requirements",
	}
}

eval_version_number(engine_version) = numeric_version {
	version = split(engine_version, ".")
	numeric_version = ((to_number(version[0]) * 100) + (to_number(version[1]) * 10)) + to_number(version[2])
}
