package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "azure_rm_roledefinition"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	roleDefinition := task[variant]
	ansLib.checkState(roleDefinition)

	actions := roleDefinition.permissions[p].actions

	allows_custom_roles_creation(actions)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(roleDefinition, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.permissions.actions", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s.permissions[%d].actions should not allow custom role creation", [variant, p]),
		"keyActualValue": sprintf("%s.permissions[%d].actions allows custom role creation", [variant, p]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "permissions", p, "actions"], []),
	}
}

customRole := "Microsoft.Authorization/roleDefinitions/write"

allows_custom_roles_creation(actions) {
	count(actions) == 1
	options := {"*", customRole}
	actions[0] == options[x]
} else {
	count(actions) > 1
	actions[x] == customRole
}
