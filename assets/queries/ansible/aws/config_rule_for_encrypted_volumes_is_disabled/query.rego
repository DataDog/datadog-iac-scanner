package Cx

import data.generic.ansible as ansLib

canonical := "config_rule"

# Emit one finding per document when no config rule has source.identifier ENCRYPTED_VOLUMES; report on first config_rule task
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	resource := task[variant]
	ansLib.checkState(resource)

	not has_encrypted_volumes_rule(id)
	first_config_rule_task(id, t)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(resource, canonical, task),
		"searchKey": sprintf("name={{%s}}", [task.name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "There should be a aws_config_rule with source.identifier equal to 'ENCRYPTED_VOLUMES'",
		"keyActualValue": "There is no aws_config_rule with source.identifier equal to 'ENCRYPTED_VOLUMES'",
	}
}

has_encrypted_volumes_rule(doc_id) {
	task := ansLib.tasks[doc_id][_]
	variant := ansLib.get_variants(canonical)[_]
	resource := task[variant]
	ansLib.checkState(resource)
	upper(resource.source.identifier) == "ENCRYPTED_VOLUMES"
}

first_config_rule_task(doc_id, task_index) {
	not earlier_config_task(doc_id, task_index)
}

earlier_config_task(doc_id, task_index) {
	some i
	task := ansLib.tasks[doc_id][i]
	i < task_index
	variant := ansLib.get_variants(canonical)[_]
	ansLib.checkState(task[variant])
}
