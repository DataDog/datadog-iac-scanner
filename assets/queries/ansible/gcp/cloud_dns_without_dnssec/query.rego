package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "gcp_dns_managed_zone"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	managed_zone := task[variant]
	ansLib.checkState(managed_zone)

	not common_lib.valid_key(managed_zone, "dnssec_config")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(managed_zone, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "gcp_dns_managed_zone.dnssec_config should be defined",
		"keyActualValue": "gcp_dns_managed_zone.dnssec_config is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	managed_zone := task[variant]
	ansLib.checkState(managed_zone)

	not common_lib.valid_key(managed_zone.dnssec_config, "state")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(managed_zone, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.dnssec_config", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "gcp_dns_managed_zone.dnssec_config.state should be defined",
		"keyActualValue": "gcp_dns_managed_zone.dnssec_config.state is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	managed_zone := task[variant]
	ansLib.checkState(managed_zone)

	managed_zone.dnssec_config.state != "on"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(managed_zone, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.dnssec_config.state", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_dns_managed_zone.dnssec_config.state should equal to 'on'",
		"keyActualValue": "gcp_dns_managed_zone.dnssec_config.state is not equal to 'on'",
	}
}
