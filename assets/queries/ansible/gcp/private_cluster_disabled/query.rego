package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "gcp_container_cluster"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cluster := task[variant]
	ansLib.checkState(cluster)

	not common_lib.valid_key(cluster, "private_cluster_config")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cluster, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "gcp_container_cluster.private_cluster_config should be defined",
		"keyActualValue": "gcp_container_cluster.private_cluster_config is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cluster := task[variant]
	ansLib.checkState(cluster)
	fields := ["enable_private_endpoint", "enable_private_nodes"]
	field := fields[f]

	not common_lib.valid_key(cluster.private_cluster_config, field)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cluster, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.private_cluster_config", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("gcp_container_cluster.private_cluster_config.%s should be defined", [fields[f]]),
		"keyActualValue": sprintf("gcp_container_cluster.private_cluster_config.%s is undefined", [fields[f]]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cluster := task[variant]
	ansLib.checkState(cluster)
	fields := ["enable_private_endpoint", "enable_private_nodes"]

	not ansLib.isAnsibleTrue(cluster.private_cluster_config[fields[f]])

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cluster, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.private_cluster_config.%s", [task.name, variant, fields[f]]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("gcp_container_cluster.private_cluster_config.%s should be true", [fields[f]]),
		"keyActualValue": sprintf("gcp_container_cluster.private_cluster_config.%s is false", [fields[f]]),
	}
}
