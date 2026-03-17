package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "gcp_container_node_pool"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	container_task := task[variant]
	ansLib.checkState(container_task)

	not common_lib.valid_key(container_task, "management")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(container_task, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "gcp_container_node_pool.management should be defined",
		"keyActualValue": "gcp_container_node_pool.management is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	container_task := task[variant]
	management := container_task.management

	ansLib.checkState(container_task)
	not common_lib.valid_key(management, "auto_upgrade")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(container_task, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.management", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "gcp_container_node_pool.management.auto_upgrade should be defined",
		"keyActualValue": "gcp_container_node_pool.management.auto_upgrade is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	container_task := task[variant]
	auto_upgrade := container_task.management.auto_upgrade

	ansLib.checkState(container_task)
	not ansLib.isAnsibleTrue(auto_upgrade)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(container_task, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.management.auto_upgrade", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_container_node_pool.management.auto_upgrade should be true",
		"keyActualValue": "gcp_container_node_pool.management.auto_upgrade is false",
	}
}
