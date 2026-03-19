package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

# Rule 1: mode == "preserve" not allowed for modules other than copy/template
# One body per canonical that can have mode but is not copy/template
preserve_check_canonicals := {"archive", "assemble", "file", "get_url", "lineinfile", "replace"}

CxPolicy[result] {
	preserve_check_canonicals[canonical]
	task := ansLib.tasks[id][e]
	variant := ansLib.get_variants(canonical)[_]
	action := task[variant]
	action.mode == "preserve"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(action, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s does not allow setting 'preserve' value for 'mode' key", [variant]),
		"keyActualValue": sprintf("'Mode' key of %s is set to 'preserve'", [variant]),
	}
}

# Rule 2: archive, assemble, copy, file, get_url, template - mode should be set when creating files/dirs
file_creation_canonicals := {"archive", "assemble", "copy", "file", "get_url", "template"}

CxPolicy[result] {
	file_creation_canonicals[canonical]
	task := ansLib.tasks[id][_]
	variant := ansLib.get_variants(canonical)[_]
	action := task[variant]

	state := object.get(action, "state", "none")
	state != "absent"
	state != "link"

	not common_lib.valid_key(action, "recurse")
	not file_module(action, variant)
	not common_lib.valid_key(action, "mode")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(action, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("All the permissions set in %s about creating files/directories", [variant]),
		"keyActualValue": sprintf("There are some permissions missing in %s and might create directory/file", [variant]),
	}
}

# Rule 3: blockinfile, htpasswd, ini_file, lineinfile - create true but mode not set
create_default_blockinfile := false
create_default_htpasswd := true
create_default_ini_file := true
create_default_lineinfile := false

CxPolicy[result] {
	task := ansLib.tasks[id][_]
	canonical := "blockinfile"
	variant := ansLib.get_variants(canonical)[_]
	action := task[variant]
	not common_lib.valid_key(action, "mode")
	object.get(action, "create", create_default_blockinfile) == true

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(action, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s 'create' key should set to 'false' or 'mode' key should be defined", [variant]),
		"keyActualValue": sprintf("%s 'create' key is set to 'true' and 'mode' key is not defined", [variant]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][_]
	canonical := "htpasswd"
	variant := ansLib.get_variants(canonical)[_]
	action := task[variant]
	not common_lib.valid_key(action, "mode")
	object.get(action, "create", create_default_htpasswd) == true

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(action, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s 'create' key should set to 'false' or 'mode' key should be defined", [variant]),
		"keyActualValue": sprintf("%s 'create' key is set to 'true' and 'mode' key is not defined", [variant]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][_]
	canonical := "ini_file"
	variant := ansLib.get_variants(canonical)[_]
	action := task[variant]
	not common_lib.valid_key(action, "mode")
	object.get(action, "create", create_default_ini_file) == true

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(action, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s 'create' key should set to 'false' or 'mode' key should be defined", [variant]),
		"keyActualValue": sprintf("%s 'create' key is set to 'true' and 'mode' key is not defined", [variant]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][_]
	canonical := "lineinfile"
	variant := ansLib.get_variants(canonical)[_]
	action := task[variant]
	not common_lib.valid_key(action, "mode")
	object.get(action, "create", create_default_lineinfile) == true

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(action, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s 'create' key should set to 'false' or 'mode' key should be defined", [variant]),
		"keyActualValue": sprintf("%s 'create' key is set to 'true' and 'mode' key is not defined", [variant]),
	}
}

file_module(action, module_name) {
	module_name == "file"
	object.get(action, "state", "file") == "file"
} else {
	module_name == "ansible.builtin.file"
	object.get(action, "state", "file") == "file"
}
