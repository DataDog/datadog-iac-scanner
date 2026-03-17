package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "autoscaling_group"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	resource := task[variant]
	ansLib.checkState(resource)

	not common_lib.valid_key(resource, "load_balancers")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(resource, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("%s.load_balancers should be set and not empty", [variant]),
		"keyActualValue": sprintf("%s.load_balancers is undefined", [variant]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	resource := task[variant]
	ansLib.checkState(resource)

	is_array(resource.load_balancers) == true
	count(resource.load_balancers) == 0

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(resource, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.load_balancers", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s.load_balancers should not be empty", [variant]),
		"keyActualValue": sprintf("%s.load_balancers is empty", [variant]),
	}
}
