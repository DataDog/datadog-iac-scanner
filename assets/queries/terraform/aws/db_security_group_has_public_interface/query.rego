package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

resource_types := {"aws_db_security_group", "aws_security_group"}
public_cidrs := {"0.0.0.0/0", "::/0"}

# Single ingress with cidr field (aws_db_security_group)
CxPolicy[result] {
	res_type := resource_types[_]
	resource := input.document[i].resource[res_type][name]
	cidrValue := public_cidrs[_]
	resource.ingress.cidr == cidrValue

	result := {
		"documentId": input.document[i].id,
		"resourceType": res_type,
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("%s[%s].ingress.cidr", [res_type, name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s[%s].ingress.cidr' should not be '0.0.0.0/0' or '::/0'", [res_type, name]),
		"keyActualValue": sprintf("'%s[%s].ingress.cidr' is '%s'", [res_type, name, resource.ingress.cidr]),
		"searchLine": common_lib.build_search_line(["resource", res_type, name, "ingress", "cidr"], []),
	}
}

# Array ingress with cidr field (aws_db_security_group)
CxPolicy[result] {
	res_type := resource_types[_]
	resource := input.document[i].resource[res_type][name]
	cidrValue := public_cidrs[_]
	resource.ingress[idx].cidr == cidrValue

	result := {
		"documentId": input.document[i].id,
		"resourceType": res_type,
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("%s[%s].ingress[%d].cidr", [res_type, name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s[%s].ingress[%d].cidr' should not be '0.0.0.0/0' or '::/0'", [res_type, name, idx]),
		"keyActualValue": sprintf("'%s[%s].ingress[%d].cidr' is '%s'", [res_type, name, idx, resource.ingress[idx].cidr]),
		"searchLine": common_lib.build_search_line(["resource", res_type, name, "ingress", idx, "cidr"], []),
	}
}

# Single ingress with cidr_blocks field (aws_security_group)
CxPolicy[result] {
	res_type := resource_types[_]
	resource := input.document[i].resource[res_type][name]
	cidrValue := public_cidrs[_]
	contains(resource.ingress.cidr_blocks[j], cidrValue)

	result := {
		"documentId": input.document[i].id,
		"resourceType": res_type,
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("%s[%s].ingress.cidr_blocks", [res_type, name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s[%s].ingress.cidr_blocks' should not contain '0.0.0.0/0' or '::/0'", [res_type, name]),
		"keyActualValue": sprintf("'%s[%s].ingress.cidr_blocks' contains '%s'", [res_type, name, cidrValue]),
		"searchLine": common_lib.build_search_line(["resource", res_type, name, "ingress", "cidr_blocks", j], []),
	}
}

# Array ingress with cidr_blocks field (aws_security_group)
CxPolicy[result] {
	res_type := resource_types[_]
	resource := input.document[i].resource[res_type][name]
	cidrValue := public_cidrs[_]
	contains(resource.ingress[idx].cidr_blocks[j], cidrValue)

	result := {
		"documentId": input.document[i].id,
		"resourceType": res_type,
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("%s[%s].ingress[%d].cidr_blocks", [res_type, name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s[%s].ingress[%d].cidr_blocks' should not contain '0.0.0.0/0' or '::/0'", [res_type, name, idx]),
		"keyActualValue": sprintf("'%s[%s].ingress[%d].cidr_blocks' contains '%s'", [res_type, name, idx, cidrValue]),
		"searchLine": common_lib.build_search_line(["resource", res_type, name, "ingress", idx, "cidr_blocks", j], []),
	}
}

# Single ingress with ipv6_cidr_blocks field (aws_security_group)
CxPolicy[result] {
	res_type := resource_types[_]
	resource := input.document[i].resource[res_type][name]
	contains(resource.ingress.ipv6_cidr_blocks[j], "::/0")

	result := {
		"documentId": input.document[i].id,
		"resourceType": res_type,
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("%s[%s].ingress.ipv6_cidr_blocks", [res_type, name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s[%s].ingress.ipv6_cidr_blocks' should not contain '::/0'", [res_type, name]),
		"keyActualValue": sprintf("'%s[%s].ingress.ipv6_cidr_blocks' contains '::/0'", [res_type, name]),
		"searchLine": common_lib.build_search_line(["resource", res_type, name, "ingress", "ipv6_cidr_blocks", j], []),
	}
}

# Array ingress with ipv6_cidr_blocks field (aws_security_group)
CxPolicy[result] {
	res_type := resource_types[_]
	resource := input.document[i].resource[res_type][name]
	contains(resource.ingress[idx].ipv6_cidr_blocks[j], "::/0")

	result := {
		"documentId": input.document[i].id,
		"resourceType": res_type,
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("%s[%s].ingress[%d].ipv6_cidr_blocks", [res_type, name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s[%s].ingress[%d].ipv6_cidr_blocks' should not contain '::/0'", [res_type, name, idx]),
		"keyActualValue": sprintf("'%s[%s].ingress[%d].ipv6_cidr_blocks' contains '::/0'", [res_type, name, idx]),
		"searchLine": common_lib.build_search_line(["resource", res_type, name, "ingress", idx, "ipv6_cidr_blocks", j], []),
	}
}
