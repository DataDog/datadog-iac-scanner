package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "azure_rm_virtualmachine"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	virtualmachine := task[variant]
	ansLib.checkState(virtualmachine)

	not common_lib.valid_key(virtualmachine, "network_interface_names")
	not common_lib.valid_key(virtualmachine, "network_interfaces")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(virtualmachine, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "azure_rm_virtualmachine.network_interface_names should be defined",
		"keyActualValue": "azure_rm_virtualmachine.network_interface_names is undefined",
	}
}
