package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "cloudtrail"

properties := {"cloudwatch_logs_role_arn", "cloudwatch_logs_log_group_arn"}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cloudtrail := task[variant]
	ansLib.checkState(cloudtrail)

	not common_lib.valid_key(cloudtrail, properties[p])

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cloudtrail, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"searchValue": properties[p],
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("name={{%s}}.{{%s}}.%s should be defined", [task.name, variant, properties[p]]),
		"keyActualValue": sprintf("name={{%s}}.{{%s}}.%s is not defined", [task.name, variant, properties[p]]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant], []),
	}
}
