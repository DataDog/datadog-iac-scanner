package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	canonical := "cloudformation"
	variant := ansLib.get_variants(canonical)[_]
	cloudformation := task[variant]
	ansLib.checkState(cloudformation)

	common_lib.valid_key(cloudformation, "template_body") == false
	common_lib.valid_key(cloudformation, "template_url") == false
	common_lib.valid_key(cloudformation, "template") == false

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cloudformation, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("%s has template, template_body or template_url set", [variant]),
		"keyActualValue": sprintf("%s does not have template, template_body or template_url set", [variant]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	canonical := "cloudformation"
	variant := ansLib.get_variants(canonical)[_]
	cloudformation := task[variant]
	ansLib.checkState(cloudformation)
	attributes := {"template_body", "template_url", "template"}
	count([x | template := attributes[x]; common_lib.valid_key(cloudformation, template)]) > 1
	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cloudformation, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s should not have more than one of the attributes template, template_body and template_url set", [variant]),
		"keyActualValue": sprintf("%s has more than one of the attributes template, template_body and template_url set", [variant]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	canonical := "cloudformation_stack_set"
	variant := ansLib.get_variants(canonical)[_]
	cloudformation := task[variant]
	ansLib.checkState(cloudformation)

	common_lib.valid_key(cloudformation, "template_body") == false
	common_lib.valid_key(cloudformation, "template_url") == false
	common_lib.valid_key(cloudformation, "template") == false

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cloudformation, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("%s has template, template_body or template_url set", [variant]),
		"keyActualValue": sprintf("%s does not have template, template_body or template_url set", [variant]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	canonical := "cloudformation_stack_set"
	variant := ansLib.get_variants(canonical)[_]
	cloudformation := task[variant]
	ansLib.checkState(cloudformation)
	attributes := {"template_body", "template_url", "template"}
	count([x | template := attributes[x]; common_lib.valid_key(cloudformation, template)]) > 1
	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cloudformation, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s should not have more than one of the attributes template, template_body and template_url set", [variant]),
		"keyActualValue": sprintf("%s has more than one of the attributes template, template_body and template_url set", [variant]),
	}
}
