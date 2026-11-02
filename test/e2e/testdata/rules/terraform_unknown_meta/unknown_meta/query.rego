package datadog

import rego.v1

finding(doc, name, attribute) := {
	"documentId": doc.id,
	"resourceType": "aws_instance",
	"resourceName": name,
	"searchKey": sprintf("aws_instance[%s].%s", [name, attribute]),
	"issueType": "IncorrectValue",
	"keyExpectedValue": attribute,
	"keyActualValue": attribute,
}

DatadogPolicy contains finding(doc, name, "ami") if {
	some doc in input.document
	some name, instance in doc.resource.aws_instance
	instance._dd_meta.unknown.ami == true
}

DatadogPolicy contains finding(doc, name, "description") if {
	some doc in input.document
	some name, instance in doc.resource.aws_instance
	instance._dd_meta
	"description" in object.keys(instance)
}
