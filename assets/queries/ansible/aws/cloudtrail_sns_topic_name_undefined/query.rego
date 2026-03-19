package Cx

import data.generic.ansible as ansLib

canonical := "cloudtrail"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)

	not instance.sns_topic_name

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "cloudtrail.sns_topic_name should be set",
		"keyActualValue": "cloudtrail.sns_topic_name is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)

	instance.sns_topic_name == null

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.sns_topic_name", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "cloudtrail.sns_topic_name should be set",
		"keyActualValue": "cloudtrail.sns_topic_name is empty",
	}
}
