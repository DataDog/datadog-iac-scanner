# Test assets/libraries/cloudformation.rego
# Make sure you have OPA version 0.49.2 installed
# Run from repo root using `opa test assets/libraries/ -v`
package generic.cloudformation

# Test normalize_cloudFormation_boolean function
test_normalize_cloudFormation_boolean_true_bool {
	result := normalize_cloudFormation_boolean(true)
	result == "true"
}

test_normalize_cloudFormation_boolean_true_string {
	result := normalize_cloudFormation_boolean("true")
	result == "true"
}

test_normalize_cloudFormation_boolean_yes {
	result := normalize_cloudFormation_boolean("yes")
	result == "true"
}

test_normalize_cloudFormation_boolean_on {
	result := normalize_cloudFormation_boolean("on")
	result == "true"
}

test_normalize_cloudFormation_boolean_false {
	result := normalize_cloudFormation_boolean(false)
	result == "false"
}

test_normalize_cloudFormation_boolean_other {
	result := normalize_cloudFormation_boolean("random")
	result == "false"
}

# Test isLoadBalancer function
test_is_load_balancer_classic {
	resource := {"Type": "AWS::ElasticLoadBalancing::LoadBalancer"}
	isLoadBalancer(resource)
}

test_is_load_balancer_v2 {
	resource := {"Type": "AWS::ElasticLoadBalancingV2::LoadBalancer"}
	isLoadBalancer(resource)
}

test_is_not_load_balancer {
	resource := {"Type": "AWS::EC2::Instance"}
	not isLoadBalancer(resource)
}

# Test checkAction function
test_check_action_wildcard_string {
	checkAction("*", "*")
}

test_check_action_contains_string {
	checkAction("s3:getobject", "getobject")
}

test_check_action_wildcard_array {
	checkAction(["*"], "*")
}

test_check_action_contains_array {
	checkAction(["s3:GetObject", "s3:PutObject"], "getobject")
}

test_check_action_no_match {
	not checkAction("s3:DeleteObject", "getobject")
}

# Test getResourcesByType function
test_get_resources_by_type_found {
	resources := [
		{"Type": "AWS::S3::Bucket", "Properties": {"BucketName": "bucket1"}},
		{"Type": "AWS::EC2::Instance", "Properties": {"InstanceType": "t2.micro"}},
		{"Type": "AWS::S3::Bucket", "Properties": {"BucketName": "bucket2"}},
	]
	result := getResourcesByType(resources, "AWS::S3::Bucket")
	count(result) == 2
	result[0].Properties.BucketName == "bucket1"
}

test_get_resources_by_type_not_found {
	resources := [
		{"Type": "AWS::S3::Bucket", "Properties": {"BucketName": "bucket1"}},
	]
	result := getResourcesByType(resources, "AWS::EC2::Instance")
	count(result) == 0
}

test_get_resources_by_type_empty {
	resources := []
	result := getResourcesByType(resources, "AWS::S3::Bucket")
	count(result) == 0
}

# Test getBucketName function
test_get_bucket_name_string {
	resource := {"Properties": {"Bucket": "my-bucket"}}
	result := getBucketName(resource)
	result == "my-bucket"
}

test_get_bucket_name_ref {
	resource := {"Properties": {"Bucket": {"Ref": "MyBucketRef"}}}
	result := getBucketName(resource)
	result == "MyBucketRef"
}

# Test get_encryption function
test_get_encryption_encrypted_true {
	resource := {"Properties": {"Encrypted": true}}
	result := get_encryption(resource)
	result == "encrypted"
}

test_get_encryption_with_encryption_specification {
	resource := {"Properties": {"EncryptionSpecification": {"SSEEnabled": true}}}
	result := get_encryption(resource)
	result == "encrypted"
}

test_get_encryption_with_kms_key {
	resource := {"Properties": {"KmsMasterKeyId": "arn:aws:kms:..."}}
	result := get_encryption(resource)
	result == "encrypted"
}

test_get_encryption_with_encryption_info {
	resource := {"Properties": {"EncryptionInfo": {"EncryptionAtRest": {}}}}
	result := get_encryption(resource)
	result == "encrypted"
}

test_get_encryption_with_encryption_options {
	resource := {"Properties": {"EncryptionOptions": {"Enabled": true}}}
	result := get_encryption(resource)
	result == "encrypted"
}

test_get_encryption_with_bucket_encryption {
	resource := {"Properties": {"BucketEncryption": {"ServerSideEncryptionConfiguration": []}}}
	result := get_encryption(resource)
	result == "encrypted"
}

test_get_encryption_with_stream_encryption {
	resource := {"Properties": {"StreamEncryption": {"StreamEncryptionType": "KMS"}}}
	result := get_encryption(resource)
	result == "encrypted"
}

test_get_encryption_unencrypted {
	resource := {"Properties": {"Name": "my-resource"}}
	result := get_encryption(resource)
	result == "unencrypted"
}

# Test get_name function
test_get_name_with_ref {
	targetName := {"Ref": "MyResource"}
	result := get_name(targetName)
	result == "MyResource"
}

test_get_name_without_ref {
	targetName := "my-resource-name"
	result := get_name(targetName)
	result == "my-resource-name"
}

# Test get_resource_name function
test_get_resource_name_with_field {
	resource := {
		"Type": "AWS::S3::Bucket",
		"Properties": {"BucketName": "my-bucket"},
	}
	result := get_resource_name(resource, "MyBucket")
	result == "my-bucket"
}

test_get_resource_name_with_tag {
	resource := {
		"Type": "AWS::EC2::Instance",
		"Properties": {"Tags": [
			{"Key": "Name", "Value": "my-instance"},
			{"Key": "Environment", "Value": "prod"},
		]},
	}
	result := get_resource_name(resource, "MyInstance")
	result == "my-instance"
}

test_get_resource_name_fallback {
	resource := {
		"Type": "AWS::EC2::Instance",
		"Properties": {},
	}
	result := get_resource_name(resource, "MyInstance")
	result == "MyInstance"
}

test_get_resource_name_elb {
	resource := {
		"Type": "AWS::ElasticLoadBalancing::LoadBalancer",
		"Properties": {"LoadBalancerName": "my-elb"},
	}
	result := get_resource_name(resource, "MyELB")
	result == "my-elb"
}

test_get_resource_name_elbv2 {
	resource := {
		"Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
		"Properties": {"Name": "my-alb"},
	}
	result := get_resource_name(resource, "MyALB")
	result == "my-alb"
}

test_get_resource_name_lambda {
	resource := {
		"Type": "AWS::Lambda::Function",
		"Properties": {"FunctionName": "my-function"},
	}
	result := get_resource_name(resource, "MyFunction")
	result == "my-function"
}

test_get_resource_name_rds {
	resource := {
		"Type": "AWS::RDS::DBInstance",
		"Properties": {"DBName": "mydb"},
	}
	result := get_resource_name(resource, "MyDB")
	result == "mydb"
}

test_get_resource_name_api_gateway {
	resource := {
		"Type": "AWS::ApiGateway::RestApi",
		"Properties": {"Name": "my-api"},
	}
	result := get_resource_name(resource, "MyAPI")
	result == "my-api"
}

test_get_resource_name_dynamodb {
	resource := {
		"Type": "AWS::DynamoDB::Table",
		"Properties": {"TableName": "my-table"},
	}
	result := get_resource_name(resource, "MyTable")
	result == "my-table"
}

test_get_resource_name_cloudtrail {
	resource := {
		"Type": "AWS::CloudTrail::Trail",
		"Properties": {"TrailName": "my-trail"},
	}
	result := get_resource_name(resource, "MyTrail")
	result == "my-trail"
}

# Test getPath function
test_get_path_with_elements {
	path := ["Resources", "MyBucket", "Properties"]
	result := getPath(path)
	result == "Resources.MyBucket.Properties."
}

test_get_path_empty {
	path := []
	result := getPath(path)
	result == ""
}

test_get_path_single_element {
	path := ["Resources"]
	result := getPath(path)
	result == "Resources."
}

# Test createSearchKey function
test_create_search_key_without_ref {
	elem := {"Name": "my-resource"}
	result := createSearchKey(elem)
	result == "=my-resource"
}

test_create_search_key_with_ref {
	elem := {"Name": {"Ref": "MyResourceRef"}}
	result := createSearchKey(elem)
	result == ".Ref=MyResourceRef"
}

# Test UDP ports map
test_udp_ports_map_dns {
	port := udpPortsMap[53]
	port == "DNS"
}

test_udp_ports_map_snmp {
	port := udpPortsMap[161]
	port == "SNMP"
}

test_udp_ports_map_postgresql {
	port := udpPortsMap[5432]
	port == "PostgreSQL"
}

test_udp_ports_map_memcached {
	port := udpPortsMap[11211]
	port == "Memcached"
}

# Test resourceFieldName map
test_resource_field_name_s3 {
	field := resourceFieldName["AWS::S3::Bucket"]
	field == "BucketName"
}

test_resource_field_name_lambda {
	field := resourceFieldName["AWS::Lambda::Function"]
	field == "FunctionName"
}

test_resource_field_name_ec2 {
	field := resourceFieldName["AWS::EC2::Instance"]
	field == ""
}

test_resource_field_name_dynamodb {
	field := resourceFieldName["AWS::DynamoDB::Table"]
	field == "TableName"
}

test_resource_field_name_rds {
	field := resourceFieldName["AWS::RDS::DBInstance"]
	field == "DBName"
}

test_resource_field_name_api_gateway_stage {
	field := resourceFieldName["AWS::ApiGateway::Stage"]
	field == "StageName"
}

test_resource_field_name_iam_role {
	field := resourceFieldName["AWS::IAM::Role"]
	field == "RoleName"
}

test_resource_field_name_kms {
	field := resourceFieldName["AWS::KMS::Key"]
	field == ""
}

# Test hasSecretManager function
test_has_secret_manager_found {
	str := "${MySecret}"
	document := {
		"MySecret": {"Type": "AWS::SecretsManager::Secret"},
		"OtherResource": {"Type": "AWS::S3::Bucket"},
	}
	hasSecretManager(str, document)
}

test_has_secret_manager_not_found {
	str := "${MySecret}"
	document := {
		"MySecret": {"Type": "AWS::S3::Bucket"},
		"OtherResource": {"Type": "AWS::EC2::Instance"},
	}
	not hasSecretManager(str, document)
}

test_has_secret_manager_missing_resource {
	str := "${NonExistentSecret}"
	document := {
		"MySecret": {"Type": "AWS::SecretsManager::Secret"},
	}
	not hasSecretManager(str, document)
}

# Test get_resource_accessibility function (basic scenarios)
test_get_resource_accessibility_unknown {
	# When no matching policy is found, accessibility should be unknown
	test_document := [{"Resources": {}}]
	result := get_resource_accessibility("my-bucket", "AWS::S3::BucketPolicy", "Bucket") with input.document as test_document

	result.accessibility == "unknown"
}
