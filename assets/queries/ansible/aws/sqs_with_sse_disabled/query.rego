package Cx

import data.generic.ansible as ansLib

canonical := "sqs_queue"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	sqsQueue := task[variant]
	ansLib.checkState(sqsQueue)

	not sqsQueue.kms_master_key_id

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(sqsQueue, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.kms_master_key_id", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "'kms_master_key_id' should be set",
		"keyActualValue": "'kms_master_key_id' is undefined",
	}
}
