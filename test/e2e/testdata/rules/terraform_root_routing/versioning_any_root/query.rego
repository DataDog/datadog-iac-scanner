package datadog

import rego.v1

versioned contains address if {
	some doc in input.document
	some versioning in doc.resource.aws_s3_bucket_versioning
	some address in versioning._dd_meta.references.bucket
}

DatadogPolicy contains result if {
	some doc in input.document
	some name, bucket in doc.resource.aws_s3_bucket
	address := bucket._dd_meta.address
	not address in versioned
	result := {
		"documentId": doc.id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s]", [name]),
	}
}
