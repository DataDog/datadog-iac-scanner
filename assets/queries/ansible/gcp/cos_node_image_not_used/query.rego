package Cx

import data.generic.ansible as ansLib

canonical := "gcp_container_node_pool"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	gcp_container := task[variant]
	ansLib.checkState(gcp_container)

	not startswith(lower(gcp_container.config.image_type), "cos")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(gcp_container, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.config.image_type", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_container_node_pool.config.image_type should start with 'COS'",
		"keyActualValue": "gcp_container_node_pool.config.image_type does not start with 'COS'",
	}
}
