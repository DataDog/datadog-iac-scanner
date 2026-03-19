package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "redshift"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	redshiftCluster := task[variant]

	redshiftCluster.command == "create"
	not common_lib.valid_key(redshiftCluster, "encrypted")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(redshiftCluster, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "redshift.encrypted should be set to true",
		"keyActualValue": "redshift.encrypted is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	redshiftCluster := task[variant]

	createOrModify(redshiftCluster.command)
	not ansLib.isAnsibleTrue(redshiftCluster.encrypted)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(redshiftCluster, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.encrypted", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "redshift.encrypted should be set to true",
		"keyActualValue": "redshift.encrypted is set to false",
	}
}

createOrModify("create") = true

createOrModify("modify") = true
