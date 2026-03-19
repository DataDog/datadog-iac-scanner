package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	canonical := "ec2_instance"
	variant := ansLib.get_variants(canonical)[_]
	ec2 := task[variant]
	ansLib.checkState(ec2)

	not common_lib.valid_key(ec2, "vpc_subnet_id")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ec2, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("%s.vpc_subnet_id should be set", [variant]),
		"keyActualValue": sprintf("%s.vpc_subnet_id is undefined", [variant]),
	}
}
