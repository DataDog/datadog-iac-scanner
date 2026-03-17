package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "gcp_container_node_pool"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	gcpContainer := task[variant]
	ansLib.checkState(gcpContainer)

	not common_lib.valid_key(gcpContainer, "management")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(gcpContainer, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "gcp_container_node_pool.management should be defined",
		"keyActualValue": "gcp_container_node_pool.management is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	gcpContainer := task[variant]
	ansLib.checkState(gcpContainer)

	not ansLib.isAnsibleTrue(gcpContainer.management.auto_repair)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(gcpContainer, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.management.auto_repair", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_container_node_pool.management.auto_repair should be set to true",
		"keyActualValue": "gcp_container_node_pool.management.auto_repair is set to false",
	}
}
