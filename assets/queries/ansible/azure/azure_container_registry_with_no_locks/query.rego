package Cx

import data.generic.common as common_lib
import data.generic.ansible as ansLib

canonical := "azure_rm_containerregistry"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	containerRegistry := task[variant]
	ansLib.checkState(containerRegistry)

	not checkLocks(containerRegistry, task)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(containerRegistry, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should be referenced by an existing lock", [variant]),
		"keyActualValue": sprintf("'%s' is not referenced by an existing lock", [variant]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant], []),
	}
}

matches(containerRegistry, taskContainerRegistry, taskLock) {
	taskLock.resource_group == containerRegistry.resource_group
} else {
	reg_id := sprintf("%s.id", [taskContainerRegistry.register])
	contains(taskLock.managed_resource_id, reg_id)
}

checkLocks(containerRegistry, taskContainerRegistry) {
	variant := ansLib.get_variants("azure_rm_lock")[_]
	taskLock := ansLib.tasks[_][_][variant]
	ansLib.checkState(taskLock)
	matches(containerRegistry, taskContainerRegistry, taskLock)
}
