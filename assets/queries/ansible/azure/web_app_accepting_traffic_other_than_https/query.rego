package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "azure_rm_webapp"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	webapp := task[variant]
	ansLib.checkState(webapp)

	not ansLib.isAnsibleTrue(webapp.https_only)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(webapp, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.https_only", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "azure_rm_webapp.https_only should be set to true or 'yes'",
		"keyActualValue": sprintf("azure_rm_webapp.https_only value is '%s'", [webapp.https_only]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	webapp := task[variant]
	ansLib.checkState(webapp)

	not common_lib.valid_key(webapp, "https_only")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(webapp, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "azure_rm_webapp.https_only should be defined",
		"keyActualValue": "azure_rm_webapp.https_only is undefined",
	}
}
