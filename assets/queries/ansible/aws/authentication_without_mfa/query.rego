package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "sts_assume_role"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	sts_assume_role := task[variant]
	ansLib.checkState(sts_assume_role)
	attributes := {"mfa_serial_number", "mfa_token"}

	not common_lib.valid_key(sts_assume_role, attributes[j])

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(sts_assume_role, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"searchValue": attributes[j],
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("sts_assume_role.%s should be set", [attributes[j]]),
		"keyActualValue": sprintf("sts_assume_role.%s is undefined", [attributes[j]]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant], []),
	}
}
