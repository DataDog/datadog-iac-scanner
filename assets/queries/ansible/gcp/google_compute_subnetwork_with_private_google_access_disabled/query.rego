package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "gcp_compute_subnetwork"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	subnetwork := task[variant]
	ansLib.checkState(subnetwork)

	not common_lib.valid_key(subnetwork, "private_ip_google_access")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(subnetwork, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("%s.private_ip_google_access should be defined and not null", [variant]),
		"keyActualValue": sprintf("%s.private_ip_google_access is undefined or null", [variant]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant], []),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	subnetwork := task[variant]
	ansLib.checkState(subnetwork)

	subnetwork.private_ip_google_access != "yes"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(subnetwork, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.private_ip_google_access", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue":  sprintf("%s.private_ip_google_access should be set to yes", [variant]),
		"keyActualValue": sprintf("%s.private_ip_google_access is set to no", [variant]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "private_ip_google_access"], []),
	}
}
