package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "gcp_container_cluster"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	container_cluster := task[variant]
	ansLib.checkState(container_cluster)

	not common_lib.valid_key(container_cluster.node_config, "service_account")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(container_cluster, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.node_config", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "'service_account' should not be default",
		"keyActualValue": "'service_account' is missing",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "node_config"], []),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	container_cluster := task[variant]
	ansLib.checkState(container_cluster)

	contains(container_cluster.node_config.service_account, "default")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(container_cluster, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.node_config.service_account", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'service_account' should not be default",
		"keyActualValue": "'service_account' is default",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "node_config", "service_account"], []),
	}
}
