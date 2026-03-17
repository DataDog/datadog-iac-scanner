package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

# ec2_instance with security_group (string) containing default
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	canonical := "ec2_instance"
	variant := ansLib.get_variants(canonical)[_]
	inst := task[variant]
	ansLib.checkState(inst)

	common_lib.valid_key(inst, "security_group")
	is_string(inst.security_group)
	contains(lower(inst.security_group), "default")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(inst, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.security_group", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'security_group' should not be using default security group",
		"keyActualValue": "'security_group' is using default security group",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "security_group"], []),
	}
}

# ec2_instance with security_groups (array) containing default
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	canonical := "ec2_instance"
	variant := ansLib.get_variants(canonical)[_]
	inst := task[variant]
	ansLib.checkState(inst)

	common_lib.valid_key(inst, "security_groups")
	is_array(inst.security_groups)
	sgName := inst.security_groups[idx]
	contains(lower(sgName), "default")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(inst, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.security_groups", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'security_groups' should not be using default security group",
		"keyActualValue": "'security_groups' is using default security group",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "security_groups"], [idx]),
	}
}
