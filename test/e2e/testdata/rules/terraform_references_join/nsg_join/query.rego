package datadog

import rego.v1

associated contains address if {
	some doc in input.document
	some association in doc.resource.azurerm_subnet_network_security_group_association
	some address in association._dd_meta.references.subnet_id
}

uncertain if {
	some doc in input.document
	some association in doc.resource.azurerm_subnet_network_security_group_association
	association.subnet_id
	not association._dd_meta.references.subnet_id
}

DatadogPolicy contains result if {
	not uncertain
	some doc in input.document
	some name, subnet in doc.resource.aws_subnet
	address := subnet._dd_meta.address
	not address in associated
	result := {
		"documentId": doc.id,
		"resourceType": "aws_subnet",
		"resourceName": name,
		"searchKey": sprintf("aws_subnet[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "subnet should be read by an association",
		"keyActualValue": address,
	}
}
