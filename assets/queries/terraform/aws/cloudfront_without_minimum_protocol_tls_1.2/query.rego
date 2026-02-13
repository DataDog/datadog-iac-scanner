package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	document := input.document[i]
	resource := document.resource.aws_cloudfront_distribution[name]
	resource.enabled == true

	not common_lib.valid_key(resource, "viewer_certificate")

	result := {
		"documentId": document.id,
		"resourceType": "aws_cloudfront_distribution",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("resource.aws_cloudfront_distribution[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("resource.aws_cloudfront_distribution[%s].viewer_certificate' should be defined and not null", [name]),
		"keyActualValue": sprintf("resource.aws_cloudfront_distribution[%s].viewer_certificate' is undefined or null", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_cloudfront_distribution", name], []),
		"remediation": "viewer_certificate {\n\tcloudfront_default_certificate = false \n\tminimum_protocol_version = \"TLSv1.2_2021\"\n\t}",
		"remediationType": "addition",
	}
}

CxPolicy[result] {
	document := input.document[i]
	resource := document.resource.aws_cloudfront_distribution[name]
	resource.enabled == true

	resource.viewer_certificate.cloudfront_default_certificate == true

	result := {
		"documentId": document.id,
		"resourceType": "aws_cloudfront_distribution",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("resource.aws_cloudfront_distribution[%s].viewer_certificate.cloudfront_default_certificate", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("resource.aws_cloudfront_distribution[%s].viewer_certificate.cloudfront_default_certificate' should be 'false'", [name]),
		"keyActualValue": sprintf("resource.aws_cloudfront_distribution[%s].viewer_certificate.cloudfront_default_certificate' is 'true'", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_cloudfront_distribution", name, "viewer_certificate", "cloudfront_default_certificate"], []),
		"remediation": json.marshal({
			"before": "true",
			"after": "false"
		}),
		"remediationType": "replacement",
	}
}

CxPolicy[result] {
	document := input.document[i]
	resource := document.resource.aws_cloudfront_distribution[name]
	resource.enabled == true

	resource.viewer_certificate.cloudfront_default_certificate == false
	protocol_version := resource.viewer_certificate.minimum_protocol_version

	not common_lib.is_recommended_tls(protocol_version)

	result := {
		"documentId": document.id,
		"resourceType": "aws_cloudfront_distribution",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("resource.aws_cloudfront_distribution[%s].viewer_certificate.minimum_protocol_version", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("resource.aws_cloudfront_distribution[%s].viewer_certificate.minimum_protocol_version' should be TLSv1.2_x", [name]),
		"keyActualValue": sprintf("resource.aws_cloudfront_distribution[%s].viewer_certificate.minimum_protocol_version' is %s", [name, protocol_version]),
		"searchLine": common_lib.build_search_line(["resource", "aws_cloudfront_distribution", name, "viewer_certificate", "minimum_protocol_version"], []),
		"remediation": json.marshal({
			"before": sprintf("%s", [protocol_version]),
			"after": "TLSv1.2_2021"
		}),
		"remediationType": "replacement",
	}
}

CxPolicy[result] {
	document := input.document[i]
	resource := document.resource.aws_cloudfront_distribution[name]
	resource.enabled == true

	resource.viewer_certificate.cloudfront_default_certificate == false
	not common_lib.valid_key(resource.viewer_certificate, "minimum_protocol_version")

	result := {
		"documentId": document.id,
		"resourceType": "aws_cloudfront_distribution",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("resource.aws_cloudfront_distribution[%s].viewer_certificate", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("resource.aws_cloudfront_distribution[%s].viewer_certificate.minimum_protocol_version' should be defined and not null", [name]),
		"keyActualValue": sprintf("resource.aws_cloudfront_distribution[%s].viewer_certificate.minimum_protocol_version' is undefined or null", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_cloudfront_distribution", name, "viewer_certificate"], []),
		"remediation": "minimum_protocol_version = \"TLSv1.2_2021\"",
		"remediationType": "addition",
	}
}

#######################################################################################################

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_cloudfront_distribution", "viewer_certificate")
	enabledKey := common_lib.get_module_equivalent_key("aws", module.source, "aws_cloudfront_distribution", "enabled")
	enabledKey == true

	not common_lib.valid_key(module, keyToCheck)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s", [name, keyToCheck]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("module[%s].%s should be defined and not null", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s is undefined or null", [name, keyToCheck]),
		"searchLine": common_lib.build_search_line(["module", name], []),
		"remediation": sprintf("%s {\n\tcloudfront_default_certificate = false \n\tminimum_protocol_version = \"TLSv1.2_2021\"\n\t}", [keyToCheck]),
		"remediationType": "addition",
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_cloudfront_distribution", "viewer_certificate")
	enabledKey := common_lib.get_module_equivalent_key("aws", module.source, "aws_cloudfront_distribution", "enabled")
	enabledKey == true

	module[keyToCheck].cloudfront_default_certificate == true

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s.cloudfront_default_certificate", [name, keyToCheck]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("module[%s].%s.cloudfront_default_certificate should be 'false'", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s.cloudfront_default_certificate is 'true'", [name, keyToCheck]),
		"searchLine": common_lib.build_search_line(["module", name, keyToCheck, "cloudfront_default_certificate"], []),
		"remediation": json.marshal({
			"before": "true",
			"after": "false"
		}),
		"remediationType": "replacement",
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_cloudfront_distribution", "viewer_certificate")
	enabledKey := common_lib.get_module_equivalent_key("aws", module.source, "aws_cloudfront_distribution", "enabled")
	enabledKey == true

	module[keyToCheck].cloudfront_default_certificate == false
	protocol_version := module[keyToCheck].minimum_protocol_version

	not common_lib.is_recommended_tls(protocol_version)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s.minimum_protocol_version", [name, keyToCheck]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("module[%s].%s.minimum_protocol_version should be TLSv1.2_x", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s.minimum_protocol_version is %s", [name, keyToCheck, protocol_version]),
		"searchLine": common_lib.build_search_line(["module", name, keyToCheck, "minimum_protocol_version"], []),
		"remediation": json.marshal({
			"before": sprintf("%s", [protocol_version]),
			"after": "TLSv1.2_2021"
		}),
		"remediationType": "replacement",
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_cloudfront_distribution", "viewer_certificate")
	enabledKey := common_lib.get_module_equivalent_key("aws", module.source, "aws_cloudfront_distribution", "enabled")
	enabledKey == true

	module[keyToCheck].cloudfront_default_certificate == false
	not common_lib.valid_key(module[keyToCheck], "minimum_protocol_version")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s", [name, keyToCheck]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("module[%s].%s.minimum_protocol_version should be defined and not null", [name, keyToCheck]),
		"keyActualValue": sprintf("module[%s].%s.minimum_protocol_version is undefined or null", [name, keyToCheck]),
		"searchLine": common_lib.build_search_line(["module", name, keyToCheck], []),
		"remediation": "minimum_protocol_version = \"TLSv1.2_2021\"",
		"remediationType": "addition",
	}
}
