package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "redshift"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	redshift := task[variant]
	ansLib.checkState(redshift)

	redshift.port == 5439

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(redshift, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.port", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "redshift.port should not be set to 5439",
		"keyActualValue": "redshift.port is set to 5439",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "port"], []),
	}
}
