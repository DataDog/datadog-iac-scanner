package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "gcp_sql_instance"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)

	ip_configuration := instance.settings.ip_configuration
	count(ip_configuration.authorized_networks) > 0
	authorized_network := ip_configuration.authorized_networks[_]
	authorized_network.value == "0.0.0.0"
	network := authorized_network.name

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.settings.ip_configuration.authorized_networks.name={{%s}}.value", [task.name, variant, network]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("gcp_sql_instance.settings.ip_configuration.authorized_networks.name={{%s}}.value address should be trusted", [network]),
		"keyActualValue": sprintf("gcp_sql_instance.settings.ip_configuration.authorized_networks.name={{%s}}.value address is not restricted: '0.0.0.0'", [network]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)

	ip_configuration := instance.settings.ip_configuration
	not common_lib.valid_key(ip_configuration, "authorized_networks")
	ansLib.isAnsibleTrue(ip_configuration.ipv4_enabled)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.settings.ip_configuration.ipv4_enabled", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_sql_instance.settings.ip_configuration.ipv4_enabled should be disabled when there are no authorized networks",
		"keyActualValue": "gcp_sql_instance.settings.ip_configuration.ipv4_enabled is enabled when there are no authorized networks",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)

	not common_lib.valid_key(instance.settings, "ip_configuration")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.settings", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "gcp_sql_instance.settings.ip_configuration should be defined and allow only trusted networks",
		"keyActualValue": "gcp_sql_instance.settings.ip_configuration is undefined",
	}
}
