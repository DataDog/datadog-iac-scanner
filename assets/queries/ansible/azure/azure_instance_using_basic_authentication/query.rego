package Cx

import data.generic.ansible as ansLib

canonical := "azure_rm_virtualmachine"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	vm := task[variant]
	ansLib.checkState(vm)
	is_linux_vm(vm)
	not vm.ssh_password_enabled == false
	not vm.linux_config.disable_password_authentication == false
	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(vm, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("'%s[%s]' should be using SSH keys for authentication", [canonical, ansLib.get_resource_name(vm, canonical, task)]),
		"keyActualValue": sprintf("'%s[%s]' is using username and password for authentication", [canonical, ansLib.get_resource_name(vm, canonical, task)]),
	}
}

is_linux_vm(vm) {
	lower(vm.os_type) == "linux"
} else {
	not vm.os_type
}
