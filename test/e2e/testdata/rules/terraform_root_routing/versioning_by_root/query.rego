package datadog

import rego.v1

versioned_roots contains root if {
	some doc in input.document
	some versioning in doc.resource.aws_s3_bucket_versioning
	some root in versioning._dd_meta.root_modules
}

DatadogPolicy contains result if {
	some doc in input.document
	some name, bucket in doc.resource.aws_s3_bucket
	some root in bucket._dd_meta.root_modules
	not root in versioned_roots
	result := {
		"documentId": doc.id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s]", [name]),
		"rootModule": root,
	}
}
