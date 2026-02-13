package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	resource := input.document[i].resource.aws_ecr_repository[name]

	not common_lib.valid_key(resource, "image_tag_mutability")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_ecr_repository",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_ecr_repository.%s", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_ecr_repository", name], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("aws_ecr_repository.%s.image_tag_mutability should be defined and not null", [name]),
		"keyActualValue": sprintf("aws_ecr_repository.%s.image_tag_mutability is undefined or null", [name]),
		"remediation": "image_tag_mutability = IMMUTABLE",
		"remediationType": "addition",
	}
}

CxPolicy[result] {
	resource := input.document[i].resource.aws_ecr_repository[name]

	resource.image_tag_mutability == "MUTABLE"

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_ecr_repository",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_ecr_repository.%s.image_tag_mutability", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_ecr_repository", name, "image_tag_mutability"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("aws_ecr_repository.%s.image_tag_mutability should be 'IMMUTABLE'", [name]),
		"keyActualValue": sprintf("aws_ecr_repository.%s.image_tag_mutability is 'MUTABLE'", [name]),
		"remediation": json.marshal({
			"before": "MUTABLE",
			"after": "IMMUTABLE"
		}),
		"remediationType": "replacement",
	}
}

#######################################################################################################

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_ecr_repository", "image_tag_mutability")

	not common_lib.valid_key(module, keyToCheck)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s]", [name]),
		"searchLine": common_lib.build_search_line(["module", name], []),
		"issueType": "MissingAttribute",
		"keyActualValue": sprintf("module[%s].%s is undefined or null", [name, keyToCheck]),
		"keyExpectedValue": sprintf("module[%s].%s should be defined and not null", [name, keyToCheck]),
		"remediation": sprintf("%s = \"IMMUTABLE\"", [keyToCheck]),
		"remediationType": "addition",
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_ecr_repository", "image_tag_mutability")

	module[keyToCheck] == "MUTABLE"

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s", [name, keyToCheck]),
		"searchLine": common_lib.build_search_line(["module", name, keyToCheck], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("module[%s].%s should be 'IMMUTABLE'", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s is 'MUTABLE'", [name, keyToCheck]),
		"remediation": json.marshal({
			"before": "MUTABLE",
			"after": "IMMUTABLE"
		}),
		"remediationType": "replacement",
	}
}
