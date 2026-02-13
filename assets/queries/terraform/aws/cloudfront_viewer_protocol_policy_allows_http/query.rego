package Cx

import data.generic.terraform as tf_lib

cache = ["default_cache_behavior", "ordered_cache_behavior"]

CxPolicy[result] {
	resource := input.document[i].resource.aws_cloudfront_distribution[name]
	# cache is not an array and is allow-all
	cache_type := cache[_]
    resource[cache_type].viewer_protocol_policy == "allow-all"

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_cloudfront_distribution",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("resource.aws_cloudfront_distribution[%s].%s.viewer_protocol_policy", [name, cache_type]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("resource.aws_cloudfront_distribution[%s].%s.viewer_protocol_policy should be 'https-only' or 'redirect-to-https'", [name, cache_type]),
		"keyActualValue": sprintf("resource.aws_cloudfront_distribution[%s].%s.viewer_protocol_policy isn't 'https-only' or 'redirect-to-https'", [name, cache_type]),
	}
}

CxPolicy[result] {
	resource := input.document[i].resource.aws_cloudfront_distribution[name]
	# cache is an array and is allow-all
	cache_type := cache[_]
    resource[cache_type][idx].viewer_protocol_policy == "allow-all"

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_cloudfront_distribution",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("resource.aws_cloudfront_distribution[%s].%s[%d].viewer_protocol_policy", [name, cache_type, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("resource.aws_cloudfront_distribution[%s].%s.viewer_protocol_policy should be 'https-only' or 'redirect-to-https'", [name, cache_type]),
		"keyActualValue": sprintf("resource.aws_cloudfront_distribution[%s].%s.viewer_protocol_policy isn't 'https-only' or 'redirect-to-https'", [name, cache_type]),
	}
}
