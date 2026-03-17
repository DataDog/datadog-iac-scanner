package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "azure_rm_aks"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	aks := task[variant]
	ansLib.checkState(aks)

	not isValidNetworkPolicy(aks.network_profile.network_policy)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(aks, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.network_profile.network_policy", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Azure AKS cluster network policy should be either 'calico' or 'azure'",
		"keyActualValue": sprintf("Azure AKS cluster network policy is %v", [aks.network_profile.network_policy]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	aks := task[variant]
	ansLib.checkState(aks)

	not common_lib.valid_key(aks, "network_profile")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(aks, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "Azure AKS cluster network profile should be defined",
		"keyActualValue": "Azure AKS cluster network profile is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	aks := task[variant]
	ansLib.checkState(aks)

	not common_lib.valid_key(aks.network_profile, "network_policy")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(aks, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "Azure AKS cluster network policy should be defined",
		"keyActualValue": "Azure AKS cluster network policy is undefined",
	}
}

isValidNetworkPolicy(policy) {
	policy == "calico"
} else {
	policy == "azure"
} else = false {
	true
}
