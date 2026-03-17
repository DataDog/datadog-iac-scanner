package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "gcp_container_cluster"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cluster := task[variant]
	ansLib.checkState(cluster)
	fields := ["network_policy", "addons_config"]
	field := fields[f]

	not common_lib.valid_key(cluster, field)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cluster, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"searchValue": field,
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("gcp_container_cluster.%s should be defined", [fields[f]]),
		"keyActualValue": sprintf("gcp_container_cluster.%s is undefined", [fields[f]]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant], []),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cluster := task[variant]
	ansLib.checkState(cluster)

	not common_lib.valid_key(cluster.addons_config, "network_policy_config")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cluster, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.addons_config", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "gcp_container_cluster.addons_config.network_policy_config should be defined",
		"keyActualValue": "gcp_container_cluster.addons_config.network_policy_config is undefined",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant], ["addons_config"]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cluster := task[variant]
	ansLib.checkState(cluster)

	ansLib.isAnsibleFalse(cluster.network_policy.enabled)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cluster, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.network_policy.enabled", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_container_cluster.network_policy.enabled should be true",
		"keyActualValue": "gcp_container_cluster.network_policy.enabled is false",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant], ["network_policy", "enabled"]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cluster := task[variant]
	ansLib.checkState(cluster)

	ansLib.isAnsibleTrue(cluster.network_policy.enabled)
	ansLib.isAnsibleTrue(cluster.addons_config.network_policy_config.disabled)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cluster, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.addons_config.network_policy_config.disabled", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_container_cluster.addons_config.network_policy_config.disabled should be set to false",
		"keyActualValue": "gcp_container_cluster.addons_config.network_policy_config.disabled is true",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant], ["addons_config", "network_policy_config", "disabled"]),
	}
}
