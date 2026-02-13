package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	required_log_types_set = {"api", "audit", "authenticator", "controllerManager", "scheduler"}
	cluster := input.document[i].resource.aws_eks_cluster[name]
	not common_lib.valid_key(cluster, "enabled_cluster_log_types")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_eks_cluster",
		"resourceName": tf_lib.get_resource_name(cluster, name),
		"searchKey": sprintf("aws_eks_cluster[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "'enabled_cluster_log_types' should be defined and not null",
		"keyActualValue": "'enabled_cluster_log_types' is undefined or null",
	}
}

#######################################################################################################

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_eks_cluster", "enabled_cluster_log_types")
	not common_lib.valid_key(module, keyToCheck)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("module[%s].%s should be defined and not null", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s is undefined or null", [name, keyToCheck]),
	}
}
