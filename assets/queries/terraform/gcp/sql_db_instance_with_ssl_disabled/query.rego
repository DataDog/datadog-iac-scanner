package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

ssl_mode_is_secure(ip_configuration) {
	ip_configuration.ssl_mode == "ENCRYPTED_ONLY"
}

ssl_mode_is_secure(ip_configuration) {
	ip_configuration.ssl_mode == "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"
}

CxPolicy[result] {
	settings := input.document[i].resource.google_sql_database_instance[name].settings

	not common_lib.valid_key(settings, "ip_configuration")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "google_sql_database_instance",
		"resourceName": tf_lib.get_resource_name(input.document[i].resource.google_sql_database_instance[name].settings, name),
		"searchKey": sprintf("google_sql_database_instance[%s].settings", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "'settings.ip_configuration' should be defined and not null",
		"keyActualValue": "'settings.ip_configuration' is undefined or null",
		"searchLine": common_lib.build_search_line(["resource", "google_sql_database_instance", name], ["settings"]),
	}
}

CxPolicy[result] {
	settings := input.document[i].resource.google_sql_database_instance[name].settings
	ip_configuration := settings.ip_configuration

	not common_lib.valid_key(ip_configuration, "require_ssl")
	not ssl_mode_is_secure(ip_configuration)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "google_sql_database_instance",
		"resourceName": tf_lib.get_resource_name(input.document[i].resource.google_sql_database_instance[name].settings, name),
		"searchKey": sprintf("google_sql_database_instance[%s].settings.ip_configuration", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "'settings.ip_configuration.ssl_mode' should be 'ENCRYPTED_ONLY' or 'TRUSTED_CLIENT_CERTIFICATE_REQUIRED', or 'settings.ip_configuration.require_ssl' should be true",
		"keyActualValue": "neither 'settings.ip_configuration.ssl_mode' is set to a secure value nor 'settings.ip_configuration.require_ssl' is true",
		"searchLine": common_lib.build_search_line(["resource", "google_sql_database_instance", name], ["settings", "ip_configuration"]),
	}
}

CxPolicy[result] {
	settings := input.document[i].resource.google_sql_database_instance[name].settings
	ip_configuration := settings.ip_configuration

	ip_configuration.require_ssl == false
	not ssl_mode_is_secure(ip_configuration)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "google_sql_database_instance",
		"resourceName": tf_lib.get_resource_name(input.document[i].resource.google_sql_database_instance[name].settings, name),
		"searchKey": sprintf("google_sql_database_instance[%s].settings.ip_configuration.require_ssl", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'settings.ip_configuration.ssl_mode' should be 'ENCRYPTED_ONLY' or 'TRUSTED_CLIENT_CERTIFICATE_REQUIRED', or 'settings.ip_configuration.require_ssl' should be true",
		"keyActualValue": "'settings.ip_configuration.require_ssl' is false and 'settings.ip_configuration.ssl_mode' is not set to a secure value",
		"searchLine": common_lib.build_search_line(["resource", "google_sql_database_instance", name], ["settings", "ip_configuration", "require_ssl"]),
	}
}
