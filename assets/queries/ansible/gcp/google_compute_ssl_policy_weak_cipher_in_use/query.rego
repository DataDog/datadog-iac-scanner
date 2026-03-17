package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "gcp_compute_ssl_policy"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	policy := task[variant]
	ansLib.checkState(policy)

	not common_lib.valid_key(policy, "min_tls_version")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(policy, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "gcp_compute_ssl_policy has min_tls_version should be set to 'TLS_1_2'",
		"keyActualValue": "gcp_compute_ssl_policy does not have min_tls_version set to 'TLS_1_2'",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	policy := task[variant]
	ansLib.checkState(policy)

	policy.min_tls_version != "TLS_1_2"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(policy, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.min_tls_version", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_compute_ssl_policy.min_tls_version has min_tls_version should be set to 'TLS_1_2'",
		"keyActualValue": "gcp_compute_ssl_policy.min_tls_version does not have min_tls_version set to 'TLS_1_2'",
	}
}
