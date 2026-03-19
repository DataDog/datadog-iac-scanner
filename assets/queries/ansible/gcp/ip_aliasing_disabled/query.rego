package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "gcp_container_cluster"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cluster := task[variant]
	ansLib.checkState(cluster)

	not common_lib.valid_key(cluster, "ip_allocation_policy")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cluster, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "gcp_container_cluster.ip_allocation_policy should be defined",
		"keyActualValue": "gcp_container_cluster.ip_allocation_policy is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cluster := task[variant]
	ansLib.checkState(cluster)

	not common_lib.valid_key(cluster.ip_allocation_policy, "use_ip_aliases")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cluster, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.ip_allocation_policy", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "gcp_container_cluster.ip_allocation_policy.use_ip_aliases should be set to true",
		"keyActualValue": "gcp_container_cluster.ip_allocation_policy.use_ip_aliases is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cluster := task[variant]
	ansLib.checkState(cluster)

	not ansLib.isAnsibleTrue(cluster.ip_allocation_policy.use_ip_aliases)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cluster, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.ip_allocation_policy.use_ip_aliases", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_container_cluster.ip_allocation_policy.use_ip_aliases should be true",
		"keyActualValue": "gcp_container_cluster.ip_allocation_policy.use_ip_aliases is false",
	}
}
