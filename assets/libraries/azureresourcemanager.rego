package generic.azureresourcemanager

import rego.v1

# gets the network security group properties for two types of resource ('Microsoft.Network/networkSecurityGroups' and 'Microsoft.Network/networkSecurityGroups/securityRules')
get_sg_info(value) := typeInfo if {
	value.type == "Microsoft.Network/networkSecurityGroups/securityRules"
	typeInfo := {
		"type": value.type,
		"properties": value.properties,
		"path": "resources.type={{Microsoft.Network/networkSecurityGroups/securityRules}}.properties",
		"sl": ["properties"],
	}
} else := typeInfo if {
	value.type == "securityRules"
	typeInfo := {
		"type": value.type,
		"properties": value.properties,
		"path": "resources.type={{securityRules}}.properties",
		"sl": ["properties"],
	}
}

# checks if source address prefix is open to the Internet
relevantSourceAddPrefix := {"*", "0.0.0.0", "internet", "any"}

source_address_prefix_is_open(properties) if {
	properties.sourceAddressPrefix == relevantSourceAddPrefix[p]
} else if {
	endswith(properties.sourceAddressPrefix, "/0")
} else if {
	properties.sourceAddressPrefixes[x] == relevantSourceAddPrefix[p]
} else if {
	endswith(properties.sourceAddressPrefixes[x], "/0")
}

contains_target_port(targetPort, port) if {
	regex.match(sprintf("(^|\\s|,)%d(-|,|$|\\s)", [targetPort]), port)
} else if {
	ports = split(port, ",")
	sublist = split(ports[var], "-")
	to_number(trim(sublist[0], " ")) <= targetPort
	to_number(trim(sublist[1], " ")) >= targetPort
} else if {
	port == "*"
}

contains_port(properties, targetPort) if {
	contains_target_port(targetPort, properties.destinationPortRange)
} else if {
	contains_target_port(targetPort, properties.destinationPortRanges[d])
}

# get_children returns an Array of all children of the resource
# doc is input.document[i]
# parent is the parent resource
get_children(doc, parent, path) := childArr if {
	resourceArr := [x | x := {"value": parent.resources[_], "path": array.concat(path, ["resources"])}]
	outerArr := get_outer_children(doc, parent.name)
	childArr := array.concat(resourceArr, outerArr)
}

get_outer_children(doc, nameParent) := outerArr if {
	outerArr := [x |
		[path, value] := walk(doc)
		startswith(value.name, nameParent)
		value.name != nameParent
		x := {"value": value, "path": path}
	]
}

getDefaultValueFromParametersIfPresent(doc, valueToCheck) := [value, propertyType] if {
	parameterName := isParameterReference(valueToCheck)
	parameter := doc.parameters[parameterName].defaultValue
	value := parameter
	propertyType := "parameter default value"
} else := [value, propertyType] if {
	not isParameterReference(valueToCheck)
	value := valueToCheck
	propertyType := "property value"
}

isParameterReference(valueToCheck) := parameterName if {
	startswith(valueToCheck, "[parameters('")
	endswith(valueToCheck, "')]")
	parameterName := trim_right(trim_left(trim_left(valueToCheck, "[parameters"), "('"), "')]")
}

isDisabledOrUndefined(doc, resource, parametersPath) if {
	object.get(resource, split(parametersPath, "."), "not defined") == "not defined"
} else if {
	value := object.get(resource, split(parametersPath, "."), "")
	[check, _] := getDefaultValueFromParametersIfPresent(doc, value)
	check == false
}
