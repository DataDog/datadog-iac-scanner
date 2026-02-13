package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	cluster := input.document[i].resource.aws_eks_cluster[name]

	not common_lib.valid_key(cluster, "encryption_config")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_eks_cluster",
		"resourceName": tf_lib.get_resource_name(cluster, name),
		"searchKey": sprintf("aws_eks_cluster[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "'encryption_config' should be defined and not null",
		"keyActualValue": "'encryption_config' is undefined or null",
		"searchLine": common_lib.build_search_line(["resource", "aws_eks_cluster", name], []),
	}
}

CxPolicy[result] {
	cluster := input.document[i].resource.aws_eks_cluster[name]

	resources := cluster.encryption_config.resources

	count({x | resource := resources[x]; resource == "secrets"}) == 0

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_eks_cluster",
		"resourceName": tf_lib.get_resource_name(cluster, name),
		"searchKey": sprintf("aws_eks_cluster[%s].encryption_config.resources", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'secrets' should be defined",
		"keyActualValue": "'secrets' is undefined",
		"searchLine": common_lib.build_search_line(["resource", "aws_eks_cluster", name, "encryption_config", "resources"], []),
	}
}

#######################################################################################################

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_eks_cluster", "encryption_config")

	not common_lib.valid_key(module, keyToCheck)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("module[%s].%s should be defined and not null", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s is undefined or null", [name, keyToCheck]),
		"searchLine": common_lib.build_search_line(["module", name], []),
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_eks_cluster", "encryption_config")

	resources := input.document[i].module[name][keyToCheck].resources

	count({x | resource := resources[x]; resource == "secrets"}) == 0

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s", [name, keyToCheck]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'secrets' should be defined",
		"keyActualValue": "'secrets' is undefined",
		"searchLine": common_lib.build_search_line(["module", name, "encryption_config", "resources"], []),
	}
}
