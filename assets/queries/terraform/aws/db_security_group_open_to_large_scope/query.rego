package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

resource_types := {"aws_db_security_group", "aws_security_group"}

# Single ingress with cidr field (aws_db_security_group)
CxPolicy[result] {
	res_type := resource_types[_]
	resource := input.document[i].resource[res_type][name]
	hosts := split(resource.ingress.cidr, "/")
	to_number(hosts[1]) <= 24

	result := {
		"documentId": input.document[i].id,
		"resourceType": res_type,
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("%s[%s].ingress.cidr", [res_type, name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s[%s].ingress.cidr' CIDR prefix > 24", [res_type, name]),
		"keyActualValue": sprintf("'%s[%s].ingress.cidr' CIDR prefix <= 24", [res_type, name]),
	}
}

# Single ingress with cidr_blocks field (aws_security_group)
CxPolicy[result] {
	res_type := resource_types[_]
	resource := input.document[i].resource[res_type][name]
	cidr := resource.ingress.cidr_blocks[j]
	hosts := split(cidr, "/")
	to_number(hosts[1]) <= 24

	result := {
		"documentId": input.document[i].id,
		"resourceType": res_type,
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("%s[%s].ingress.cidr_blocks", [res_type, name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s[%s].ingress.cidr_blocks' CIDR prefix > 24", [res_type, name]),
		"keyActualValue": sprintf("'%s[%s].ingress.cidr_blocks' contains '%s' with prefix <= 24", [res_type, name, cidr]),
		"searchLine": common_lib.build_search_line(["resource", res_type, name, "ingress", "cidr_blocks", j], []),
	}
}

# Array ingress with cidr_blocks field (aws_security_group)
CxPolicy[result] {
	res_type := resource_types[_]
	resource := input.document[i].resource[res_type][name]
	cidr := resource.ingress[idx].cidr_blocks[j]
	hosts := split(cidr, "/")
	to_number(hosts[1]) <= 24

	result := {
		"documentId": input.document[i].id,
		"resourceType": res_type,
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("%s[%s].ingress[%d].cidr_blocks", [res_type, name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s[%s].ingress[%d].cidr_blocks' CIDR prefix > 24", [res_type, name, idx]),
		"keyActualValue": sprintf("'%s[%s].ingress[%d].cidr_blocks' contains '%s' with prefix <= 24", [res_type, name, idx, cidr]),
		"searchLine": common_lib.build_search_line(["resource", res_type, name, "ingress", idx, "cidr_blocks", j], []),
	}
}
