package datadog

import rego.v1

associated_subnets contains [root, address] if {
	some doc in input.document
	some association in doc.resource.azurerm_subnet_network_security_group_association
	some root in association._dd_meta.root_modules
	some address in association._dd_meta.references.subnet_id
}

uncertain_roots contains root if {
	some doc in input.document
	some association in doc.resource.azurerm_subnet_network_security_group_association
	association.subnet_id
	not association._dd_meta.references.subnet_id
	some root in association._dd_meta.root_modules
}

DatadogPolicy contains result if {
	some doc in input.document
	some name, subnet in doc.resource.aws_subnet
	some root in subnet._dd_meta.root_modules
	not root in uncertain_roots
	not [root, subnet._dd_meta.address] in associated_subnets
	result := {
		"documentId": doc.id,
		"resourceType": "aws_subnet",
		"resourceName": name,
		"searchKey": sprintf("aws_subnet[%s]", [name]),
		"rootModule": root,
		"issueType": "MissingAttribute",
		"keyExpectedValue": "subnet should be read by an association",
		"keyActualValue": subnet._dd_meta.address,
	}
}
