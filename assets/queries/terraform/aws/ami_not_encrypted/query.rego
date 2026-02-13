package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

CxPolicy[result] {
	ami := input.document[i].resource.aws_ami[name]
	ami.ebs_block_device.encrypted == false

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_ami",
		"resourceName": tf_lib.get_resource_name(ami, name),
		"searchKey": sprintf("aws_ami[%s].ebs_block_device.encrypted", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_ami", name,"ebs_block_device","encrypted"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'rule.ebs_block_device.encrypted' should be 'true'",
		"keyActualValue": "'rule.ebs_block_device.encrypted' is not 'true'",
		"remediation": json.marshal({
			"before": "false",
			"after": "true"
		}),
		"remediationType": "replacement",
	}
}

CxPolicy[result] {
	ami := input.document[i].resource.aws_ami[name]
	common_lib.valid_key(ami, "ebs_block_device")
	not common_lib.valid_key(ami.ebs_block_device, "encrypted")
	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_ami",
		"resourceName": tf_lib.get_resource_name(ami, name),
		"searchKey": sprintf("aws_ami[%s].ebs_block_device", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_ami", name,"ebs_block_device"], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "'rule.ebs_block_device.encrypted' should be 'true'",
		"keyActualValue": "'rule.ebs_block_device' is undefined",
		"remediation": "encrypted = true",
		"remediationType": "addition",
	}
}

CxPolicy[result] {
	ami := input.document[i].resource.aws_ami[name]
	not common_lib.valid_key(ami, "ebs_block_device")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_ami",
		"resourceName": tf_lib.get_resource_name(ami, name),
		"searchKey": sprintf("aws_ami[%s]", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_ami", name], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "'rule.ebs_block_device.encrypted' should be 'true'",
		"keyActualValue": "'rule.ebs_block_device' is undefined",
		"remediation": "ebs_block_device {\n\tencrypted = true\n\t}",
		"remediationType": "addition",
	}
}

#######################################################################################################

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_ami", "ebs_block_device")
	module[keyToCheck].encrypted == false

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s.encrypted", [name, keyToCheck]),
		"searchLine": common_lib.build_search_line(["module", name, keyToCheck, "encrypted"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("module[%s].%s.encrypted should be 'true'", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s.encrypted is not 'true'", [name, keyToCheck]),
		"remediation": json.marshal({
			"before": "false",
			"after": "true"
		}),
		"remediationType": "replacement",
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_ami", "ebs_block_device")
	common_lib.valid_key(module, keyToCheck)
	not common_lib.valid_key(module[keyToCheck], "encrypted")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s]", [name]),
		"searchLine": common_lib.build_search_line(["module", name, keyToCheck], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("module[%s].%s.encrypted should be 'true'", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s.encrypted is undefined", [name, keyToCheck]),
		"remediation": sprintf("%s {\n\tencrypted = true\n\t}", [keyToCheck]),
		"remediationType": "addition",
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_ami", "ebs_block_device")
	not common_lib.valid_key(module, keyToCheck)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s]", [name]),
		"searchLine": common_lib.build_search_line(["module", name], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("module[%s].%s.encrypted should be 'true'", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s is undefined", [name, keyToCheck]),
		"remediation": "ebs_block_device{ \n\tencrypted = true\n\t}",
		"remediationType": "addition",
	}
}
