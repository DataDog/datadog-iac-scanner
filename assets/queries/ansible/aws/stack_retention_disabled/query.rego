package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "cloudformation_stack_set"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cloudformation_stack_set := task[variant]
	ansLib.checkState(cloudformation_stack_set)

	not common_lib.valid_key(cloudformation_stack_set, "purge_stacks")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cloudformation_stack_set, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "cloudformation_stack_set.purge_stacks should be set",
		"keyActualValue": "cloudformation_stack_set.purge_stacks is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cloudformation_stack_set := task[variant]
	ansLib.checkState(cloudformation_stack_set)

	common_lib.valid_key(cloudformation_stack_set, "purge_stacks")
	cloudformation_stack_set.purge_stacks

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cloudformation_stack_set, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.purge_stacks", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "cloudformation_stack_set.purge_stacks should be set to false",
		"keyActualValue": "cloudformation_stack_set.purge_stacks is true",
	}
}
