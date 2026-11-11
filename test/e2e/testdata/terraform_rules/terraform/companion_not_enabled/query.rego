package datadog

import rego.v1

import data.generic.common as common

import data.generic.terraform as tf

DatadogPolicy contains result if {
	some b in tf.blocks("aws_s3_bucket")
	not versioned(b)
	result := common.finding(b, [], {})
}

versioned(b) if {
	some v in tf.related(b, "aws_s3_bucket_versioning", "bucket")
	some c in tf.nested(v, "versioning_configuration")
	c.status == "Enabled"
}
