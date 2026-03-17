package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "gcp_container_cluster"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	container_cluster := task[variant]
	ansLib.checkState(container_cluster)

	not common_lib.valid_key(container_cluster, "master_authorized_networks_config")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(container_cluster, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "gcp_container_cluster.master_authorized_networks_config should be defined",
		"keyActualValue": "gcp_container_cluster.master_authorized_networks_config is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	container_cluster := task[variant]
	ansLib.checkState(container_cluster)

	not common_lib.valid_key(container_cluster.master_authorized_networks_config, "enabled")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(container_cluster, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.master_authorized_networks_config", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "gcp_container_cluster.master_authorized_networks_config.enabled should be defined",
		"keyActualValue": "gcp_container_cluster.master_authorized_networks_config.enabled is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	container_cluster := task[variant]
	ansLib.checkState(container_cluster)

	not ansLib.isAnsibleTrue(container_cluster.master_authorized_networks_config.enabled)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(container_cluster, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.master_authorized_networks_config.enabled", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_container_cluster.master_authorized_networks_config.enabled should be true",
		"keyActualValue": "gcp_container_cluster.master_authorized_networks_config.enabled is false",
	}
}
