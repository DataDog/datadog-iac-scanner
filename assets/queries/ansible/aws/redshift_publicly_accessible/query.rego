package Cx

import data.generic.ansible as ansLib

canonical := "redshift"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	redshift := task[variant]
	ansLib.checkState(redshift)

	ansLib.isAnsibleTrue(redshift.publicly_accessible)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(redshift, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.publicly_accessible", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "redshift.publicly_accessible should be set to false",
		"keyActualValue": "redshift.publicly_accessible is true",
	}
}
