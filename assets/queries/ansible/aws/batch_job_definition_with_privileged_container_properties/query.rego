package Cx

import data.generic.ansible as ansLib

canonical := "batch_job_definition"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	batch_job_definition := task[variant]

	ansLib.checkState(batch_job_definition)
	ansLib.isAnsibleTrue(batch_job_definition.privileged)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(batch_job_definition, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.privileged", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("name={{%s}}.{{%s}}.privileged should be set to 'false' or not set", [task.name, variant]),
		"keyActualValue": sprintf("name={{%s}}.{{%s}}.privileged is 'true'", [task.name, variant]),
	}
}
