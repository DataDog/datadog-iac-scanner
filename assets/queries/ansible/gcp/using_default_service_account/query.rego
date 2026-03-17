package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "gcp_compute_instance"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)

	instance.auth_kind == "serviceaccount"
	not common_lib.valid_key(instance, "service_account_email")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "gcp_compute_instance.service_account_email should be defined",
		"keyActualValue": "gcp_compute_instance.service_account_email is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)

	instance.auth_kind == "serviceaccount"
	email := instance.service_account_email
	is_string(email)
	count(email) == 0

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.service_account_email", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_compute_instance.service_account_email should not be empty",
		"keyActualValue": "gcp_compute_instance.service_account_email is empty",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)

	instance.auth_kind == "serviceaccount"
	email := instance.service_account_email
	is_string(email)
	count(email) > 0
	not contains(email, "@")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.service_account_email", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_compute_instance.service_account_email should be an email",
		"keyActualValue": "gcp_compute_instance.service_account_email is not an email",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)

	instance.auth_kind == "serviceaccount"
	email := instance.service_account_email
	contains(email, "@developer.gserviceaccount.com")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.service_account_email", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_compute_instance.service_account_email should not be a default Google Compute Engine service account",
		"keyActualValue": "gcp_compute_instance.service_account_email is a default Google Compute Engine service account",
	}
}
