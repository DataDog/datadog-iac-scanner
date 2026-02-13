package Cx

import data.generic.terraform as tf_lib

CxPolicy[result] {
	resource := input.document[i].resource.azurerm_network_security_rule[var0]
	upper(resource.access) == "ALLOW"
	upper(resource.direction) == "INBOUND"

	isRelevantProtocol(resource.protocol)
	isRelevantPort(resource.destination_port_range)
    hasRelevantSourceAddress(resource)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "azurerm_network_security_rule",
		"resourceName": tf_lib.get_resource_name(resource, var0),
		"searchKey": sprintf("azurerm_network_security_rule[%s].destination_port_range", [var0]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'azurerm_network_security_rule.%s.destination_port_range' cannot be 3389", [var0]),
		"keyActualValue": sprintf("'azurerm_network_security_rule.%s.destination_port_range' might be 3389", [var0]),
	}
}

isRelevantProtocol(protocol) = allow {
	upper(protocol) != "UDP"
	upper(protocol) != "ICMP"
	allow = true
}

isRelevantPort(port) = allow {
	regex.match("(^|\\s|,)3389(-|,|$|\\s)", port)
	allow = true
}

else = allow {
	ports = split(port, ",")
	sublist = split(ports[var], "-")
	to_number(trim(sublist[0], " ")) <= 3389
	to_number(trim(sublist[1], " ")) >= 3389
	allow = true
}

hasRelevantSourceAddress(resource) {
	isRelevantAddressPrefix(resource.source_address_prefix)
}

hasRelevantSourceAddress(resource) {
	isRelevantAddressPrefixes(resource.source_address_prefixes)
}

isRelevantAddressPrefixes(prefixes) = allow {
    some prefix
    isRelevantAddressPrefix(prefixes[prefix])
    allow = true
}

isRelevantAddressPrefix(prefix) = allow {
	prefix == "*"
	allow = true
}

else = allow {
	prefix == "0.0.0.0"
	allow = true
}

else = allow {
	endswith(prefix, "/0")
	allow = true
}

else = allow {
	lower(prefix) == "internet"
	allow = true
}

else = allow {
	lower(prefix) == "any"
	allow = true
}
