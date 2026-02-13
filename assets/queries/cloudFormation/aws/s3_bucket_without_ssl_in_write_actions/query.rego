package Cx

import data.generic.cloudformation as cf_lib
import data.generic.common as common_lib

CxPolicy[result] {
	document := input.document[i]
	resources := document.Resources

	resource := resources[resourceName]
	resource.Type == "AWS::S3::Bucket"

	not bucketHasPolicy(resource, resourceName, resources)

	result := {
		"documentId": document.id,
		"resourceType": resource.Type,
		"resourceName": cf_lib.get_resource_name(resource, resourceName),
		"searchKey": buildSearchKey(resource, resourceName),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("Resources.%s bucket has a policy that enforces SSL", [resourceName]),
		"keyActualValue": sprintf("Resources.%s bucket doesn't have a policy", [resourceName]),
		"searchLine": buildSearchLine(resource, resourceName),
	}
}

CxPolicy[result] {
	document := input.document[i]
	resources := document.Resources

	resource := resources[resourceName]
	resource.Type == "AWS::S3::Bucket"

	bucketHasPolicy(resource, resourceName, resources)
	not bucketHasPolicyWithValidSslVerification(resource, resourceName, resources)

	result := {
		"documentId": document.id,
		"resourceType": resource.Type,
		"resourceName": cf_lib.get_resource_name(resource, resourceName),
		"searchKey": buildSearchKey(resource, resourceName),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("Resources.%s bucket has a policy that enforces SSL", [resourceName]),
		"keyActualValue": sprintf("Resources.%s bucket doesn't have a policy or has a policy that doesn't enforce SSL", [resourceName]),
		"searchLine": buildSearchLine(resource, resourceName),
	}
}

buildSearchKey(resource, resourceName) = searchKey {
	searchKey := sprintf("Resources.%s.Properties.BucketName=%s", [resourceName, resource.Properties.BucketName])
} else = searchKey {
	searchKey := sprintf("Resources.%s", [resourceName])
}

buildSearchLine(resource, resourceName) = searchLine {
	searchLine := common_lib.build_search_line(["Resources", resourceName, "Properties"], [resource.Properties.BucketName])
} else = searchLine {
	searchLine := common_lib.build_search_line(["Resources", resourceName], [])
}

bucketHasPolicy(bucket, bucketLogicalName, resources) {
	resources[a].Type == "AWS::S3::BucketPolicy"
	cf_lib.getBucketName(resources[a]) == bucket.Properties.BucketName
} else {
	resources[a].Type == "AWS::S3::BucketPolicy"
	cf_lib.getBucketName(resources[a]) == bucketLogicalName
}

bucketHasPolicyWithValidSslVerification(bucket, bucketLogicalName, resources) {
	resources[a].Type == "AWS::S3::BucketPolicy"
	cf_lib.getBucketName(resources[a]) == bucket.Properties.BucketName

	isValidSslPolicyStatement(resources[a].Properties.PolicyDocument.Statement)
} else {
	resources[a].Type == "AWS::S3::BucketPolicy"
	cf_lib.getBucketName(resources[a]) == bucketLogicalName

	isValidSslPolicyStatement(resources[a].Properties.PolicyDocument.Statement)
}

isUnsafeAction("s3:*") = true

isUnsafeAction("s3:PutObject") = true

isValidSslPolicyStatement(stmt) {
	is_array(stmt)
	st := stmt[s]
	st.Effect == "Deny"
	isUnsafeAction(st.Action)
	cf_lib.normalize_cloudFormation_boolean(st.Condition.Bool["aws:SecureTransport"]) == "false"
} else {
	is_array(stmt)
	st := stmt[s]
	st.Effect == "Deny"
	is_array(st.Action)
	action := st.Action[i]
	isUnsafeAction(action)
	cf_lib.normalize_cloudFormation_boolean(st.Condition.Bool["aws:SecureTransport"]) == "false"
} 
else {
	is_object(stmt)
	stmt.Effect == "Deny"
	isUnsafeAction(stmt.Action)
	cf_lib.normalize_cloudFormation_boolean(stmt.Condition.Bool["aws:SecureTransport"]) == "false"
}
else {
	is_array(stmt)
	st := stmt[s]
	st.Effect == "Allow"
	isUnsafeAction(st.Action)
	cf_lib.normalize_cloudFormation_boolean(st.Condition.Bool["aws:SecureTransport"]) == "true"
} else {
	is_array(stmt)
	st := stmt[s]
	st.Effect == "Allow"
	is_array(st.Action)
	action := st.Action[i]
	isUnsafeAction(action)
	cf_lib.normalize_cloudFormation_boolean(st.Condition.Bool["aws:SecureTransport"]) == "true"
} 
else {
	is_object(stmt)
	stmt.Effect == "Allow"
	isUnsafeAction(stmt.Action)
	cf_lib.normalize_cloudFormation_boolean(stmt.Condition.Bool["aws:SecureTransport"]) == "true"
}
