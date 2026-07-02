package datadog

import rego.v1

DatadogPolicy contains result if {
	resource := input.document[i].resource.aws_s3_bucket[name]
	role = "authenticated-read"
	resource.acl == role

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("aws_s3_bucket[%s].acl", [name]),
	}
}
