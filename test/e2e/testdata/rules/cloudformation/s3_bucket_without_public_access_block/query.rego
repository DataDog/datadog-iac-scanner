package datadog

import rego.v1

DatadogPolicy contains result if {
	some i, name
	resource := input.document[i].Resources[name]
	resource.Type == "AWS::S3::Bucket"

	not has_public_access_block(resource)

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("Resources.{{%s}}", [name]),
		"resourceName": name,
		"resourceType": "AWS::S3::Bucket",
	}
}

has_public_access_block(resource) if {
	object.get(resource, "Properties", {}).PublicAccessBlockConfiguration
}
