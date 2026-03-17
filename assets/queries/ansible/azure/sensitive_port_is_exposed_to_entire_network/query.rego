package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "azure_rm_securitygroup"

CxPolicy[result] {
	tcpPortsMap := common_lib.tcpPortsMap

	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	securitygroup := task[variant]
	ansLib.checkState(securitygroup)
	resource := securitygroup.rules[r]

	portContent := tcpPortsMap[port]
	portNumber := port
	portName := portContent
	protocol := getProtocolList(resource.protocol)[_]

	upper(resource.access) == "ALLOW"
	inbound_direction(resource)
	endswith(resource.source_address_prefix, "/0")
	containsDestinationPort(portNumber, resource)
	isTCPorUDP(protocol)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(securitygroup, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.rules.name={{%s}}.destination_port_range", [task.name, variant, resource.name]),
		"searchValue": sprintf("%s,%d", [protocol, portNumber]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s (%s:%d) should not be allowed", [portName, protocol, portNumber]),
		"keyActualValue": sprintf("%s (%s:%d) is allowed", [portName, protocol, portNumber]),
	}
}

getProtocolList(protocol) = list {
	protocol == "*"
	list := ["TCP", "UDP", "Icmp"]
} else = list {
	upper(protocol) == "TCP"
	list := ["TCP"]
} else = list {
	upper(protocol) == "UDP"
	list := ["UDP"]
} else = list {
	upper(protocol) == "ICMP"
	list := ["Icmp"]
}

containsDestinationPort(port, resource) = containing {
	is_string(resource.destination_port_range)
	containing := containsDP(port, resource.destination_port_range)
} else = containing {
	is_array(resource.destination_port_range)
	containing := containsDP(port, resource.destination_port_range[i])
}

containsDP(port, dpr) = containing {
	regex.match(sprintf("(^|\\s|,)%d(-|,|$|\\s)", [port]), dpr)
	containing := true
} else = containing {
	some var
	ports := split(dpr, ",")
	sublist := split(ports[var], "-")
	to_number(trim(sublist[0], " ")) <= port
	to_number(trim(sublist[1], " ")) >= port
	containing := true
}

isTCPorUDP(protocol) = is {
	is := upper(protocol) != "ICMP"
}

inbound_direction(resource) {
	upper(resource.direction) == "INBOUND"
} else {
	not common_lib.valid_key(resource, "direction")
}
