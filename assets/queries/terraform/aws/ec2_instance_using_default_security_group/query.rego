package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	doc := input.document[i]
	resource := doc.resource.aws_instance[name]

	sgs := {"security_groups", "vpc_security_group_ids"}

	sgInfo := resource[sgs[s]][_]

	contains(lower(sgInfo), "default")

	result := {
		"documentId": doc.id,
		"resourceType": "aws_instance",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_instance[%s].%s", [name, sgs[s]]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("aws_instance[%s].%s should not be using default security group", [name, s]),
		"keyActualValue": sprintf("aws_instance[%s].%s is using at least one default security group", [name, s]),
		"searchLine": common_lib.build_search_line(["resource", "aws_instance", name, sgs[s]], []),
	}
}

#######################################################################################################

CxPolicy[result] {
	module := input.document[i].module[name]

	sgs := {"security_groups", "vpc_security_group_ids"}
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_instance", sgs[s])

	sgInfo := module[keyToCheck][_]

	contains(lower(sgInfo), "default")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s", [name, keyToCheck]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("module[%s].%s should not be using default security group", [name, s]),
		"keyActualValue": sprintf("module[%s].%s is using at least one default security group", [name, s]),
		"searchLine": common_lib.build_search_line(["module", name, keyToCheck], []),
	}
}
