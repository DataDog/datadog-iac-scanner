package datadog

import rego.v1

DatadogPolicy contains {
	"documentId": doc.id,
	"resourceType": "aws_s3_bucket",
	"resourceName": name,
	"searchKey": sprintf("aws_s3_bucket[%s].acl", [name]),
	"issueType": "IncorrectValue",
	"keyExpectedValue": "acl is not public-read",
	"keyActualValue": "acl is public-read",
} if {
	some doc in input.document
	some name, bucket in doc.resource.aws_s3_bucket
	bucket.acl == "public-read"
}
