package Cx

import data.generic.ansible as ansLib

canonical := "gcp_container_cluster"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cluster := task[variant]
	ansLib.checkState(cluster)

	ansLib.isAnsibleTrue(cluster.legacy_abac.enabled)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cluster, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.legacy_abac.enabled", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_container_cluster.legacy_abac.enabled should be set to false",
		"keyActualValue": "gcp_container_cluster.legacy_abac.enabled is true",
	}
}
