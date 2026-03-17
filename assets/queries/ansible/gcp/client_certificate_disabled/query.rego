package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "gcp_container_cluster"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cluster := task[variant]
	ansLib.checkState(cluster)

	not common_lib.valid_key(cluster, "master_auth")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cluster, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "gcp_container_cluster.master_auth should be defined",
		"keyActualValue": "gcp_container_cluster.master_auth is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cluster := task[variant]
	ansLib.checkState(cluster)

	not common_lib.valid_key(cluster.master_auth, "client_certificate_config")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cluster, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.master_auth", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "gcp_container_cluster.master_auth.client_certificate_config should be defined",
		"keyActualValue": "gcp_container_cluster.master_auth.client_certificate_config is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cluster := task[variant]
	ansLib.checkState(cluster)

	ansLib.isAnsibleFalse(cluster.master_auth.client_certificate_config.issue_client_certificate)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cluster, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.master_auth.client_certificate_config.issue_client_certificate", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_container_cluster.master_auth.password should be true",
		"keyActualValue": "gcp_container_cluster.master_auth.password is false",
	}
}
