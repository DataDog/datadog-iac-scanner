package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "azure_rm_adserviceprincipal"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	ad := task[variant]
	ansLib.checkState(ad)

	common_lib.emptyOrNull(ad.ad_user)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ad, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.ad_user", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "azure_rm_adserviceprincipal.ad_user should be neither empty nor null",
		"keyActualValue": "azure_rm_adserviceprincipal.ad_user is empty or null",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	ad := task[variant]
	ansLib.checkState(ad)

	is_string(ad.ad_user)
	check_predictable(ad.ad_user)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ad, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.ad_user", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "azure_rm_adserviceprincipal.ad_user should not be predictable",
		"keyActualValue": "azure_rm_adserviceprincipal.ad_user is predictable",
	}
}

check_predictable(name) {
	predictable_names := {"admin", "administrator", "sqladmin", "root", "user", "azure_admin", "azure_administrator", "guest"}
	some i
	predictable_names[i] == lower(name)
}
