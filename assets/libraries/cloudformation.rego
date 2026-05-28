package generic.cloudformation

import data.generic.common as common_lib


normalize_cloudFormation_boolean(boolOrString) = string {
	boolOrString == true
	string = "true"
} else = string {
	lower(boolOrString) == "true"
	string = "true"
} else = string {
	lower(boolOrString) == "on"
	string = "true"
} else = string {
	lower(boolOrString) == "yes"
	string = "true"
} else = string {
	string = "false"
}

# Find out if the document has a resource type equals to 'AWS::SecretsManager::Secret'
hasSecretManager(str, document) {
	selectedSecret := strings.replace_n({"${": "", "}": ""}, regex.find_n(`\${\w+}`, str, 1)[0])
	document[selectedSecret].Type == "AWS::SecretsManager::Secret"
}

# Check if the type is ELB
isLoadBalancer(resource) {
	resource.Type == "AWS::ElasticLoadBalancing::LoadBalancer"
}

# Check if the type is ELB
isLoadBalancer(resource) {
	resource.Type == "AWS::ElasticLoadBalancingV2::LoadBalancer"
}

# Check if there is an action inside an array
checkAction(currentAction, actionToCompare) {
	is_string(currentAction)
	currentAction == "*"
	currentAction == actionToCompare
} else {
	is_string(currentAction)
	contains(lower(currentAction), actionToCompare)
} else {
	is_array(currentAction)
	action := currentAction[_]
	action == "*"
	action == actionToCompare
} else {
	is_array(currentAction)
	action := currentAction[_]
	contains(lower(action), actionToCompare)
}

# Dictionary of UDP ports
udpPortsMap = {
	53: "DNS",
	137: "NetBIOS Name Service",
	138: "NetBIOS Datagram Service",
	139: "NetBIOS Session Service",
	161: "SNMP",
	389: "LDAP",
	1434: "MSSQL Browser",
	2483: "Oracle DB SSL",
	2484: "Oracle DB SSL",
	5432: "PostgreSQL",
	11211: "Memcached",
	11214: "Memcached SSL",
	11215: "Memcached SSL",
}

# Get content of the resource(s) based on the type
getResourcesByType(resources, type) = list {
	list = [resource | resources[i].Type == type; resource := resources[i]]
}

getBucketName(resource) = name {
	name := resource.Properties.Bucket
	not common_lib.valid_key(name, "Ref")
} else = name {
	name := resource.Properties.Bucket.Ref
}

get_encryption(resource) = encryption {
	resource.Properties.Encrypted == true
	encryption := "encrypted"
} else = encryption {
	fields := {"EncryptionSpecification", "KmsMasterKeyId", "EncryptionInfo", "EncryptionOptions", "BucketEncryption", "StreamEncryption"}
	common_lib.valid_key(resource.Properties, fields[_])
	encryption := "encrypted"
} else = encryption {
	encryption := "unencrypted"
}

get_name(targetName) = name {
	common_lib.valid_key(targetName, "Ref")
	name := targetName.Ref
} else = name {
	not common_lib.valid_key(targetName, "Ref")
	name := targetName
}

get_resource_accessibility(nameRef, type, key) = info {
	document := input.document
	policy := document[_].Resources[_]
	policy.Type == type

	keys := policy.Properties[key]

	get_name(keys) == nameRef

	statement := common_lib.get_statement(policy.Properties.PolicyDocument)
	common_lib.any_principal(statement)
	common_lib.is_allow_effect(statement)

	info := {"accessibility": "public", "policy": policy.Properties.PolicyDocument}
} else = info {
	document := input.document
	policy := document[_].Resources[_]
	policy.Type == type

	keys := policy.Properties[key]

	get_name(keys[_]) == nameRef

	statement := common_lib.get_statement(policy.Properties.PolicyDocument)
	common_lib.any_principal(statement)
	common_lib.is_allow_effect(statement)

	info := {"accessibility": "public", "policy": policy.Properties.PolicyDocument}
} else = info {
	document := input.document
	policy := document[_].Resources[_]
	policy.Type == type

	keys := policy.Properties[key]

	get_name(keys) == nameRef

	info := {"accessibility": "hasPolicy", "policy": policy.Properties.PolicyDocument}
} else = info {
	document := input.document
	policy := document[_].Resources[_]
	policy.Type == type

	keys := policy.Properties[key]

	get_name(keys[_]) == nameRef

	info := {"accessibility": "hasPolicy", "policy": policy.Properties.PolicyDocument}
} else = info {
	info := {"accessibility": "unknown", "policy": ""}
}

resourceFieldName = {
	"AWS::Config::ConfigRule": "ConfigRuleName",
	"AWS::ElasticLoadBalancing::LoadBalancer": "LoadBalancerName",
	"AWS::ElasticLoadBalancingV2::LoadBalancer": "Name",
	"Alexa::ASK::Skill": "",
	"AWS::AmazonMQ::Broker": "BrokerName",
	"AWS::Amplify::App": "Name",
	"AWS::ApiGateway::Stage": "StageName",
	"AWS::ApiGatewayV2::Stage": "StageName",
	"AWS::ApiGateway::Deployment": "StageName",
	"AWS::ApiGateway::RestApi": "Name",
	"AWS::ApiGateway::Method": "OperationName",
	"AWS::ApiGateway::Authorizer": "Name",
	"AWS::ApiGatewayV2::Authorizer": "Name",
	"AWS::ApiGatewayV2::Api": "Name",
	"AWS::ApiGateway::DomainName": "DomainName",
	"AWS::AutoScaling::AutoScalingGroup": "AutoScalingGroupName",
	"AWS::RDS::DBInstance": "DBName",
	"AWS::Batch::JobDefinition": "JobDefinitionName",
	"AWS::CloudFront::Distribution": "",
	"AWS::EC2::Instance": "",
	"AWS::CloudTrail::Trail": "TrailName",
	"AWS::Route53::HostedZone": "Name",
	"AWS::KMS::Key": "",
	"AWS::DocDB::DBCluster": "",
	"AWS::Neptune::DBCluster": "",
	"AWS::RDS::DBCluster": "DatabaseName",
	"AWS::RDS::GlobalCluster": "",
	"AWS::Redshift::Cluster": "DBName",
	"AWS::CodeBuild::Project": "Name",
	"AWS::Cognito::UserPool": "UserPoolName",
	"AWS::Config::ConfigurationAggregator": "ConfigurationAggregatorName",
	"AWS::IAM::Role": "RoleName",
	"AWS::EC2::SecurityGroup": "GroupName",
	"AWS::RDS::DBSecurityGroup": "",
	"AWS::DirectoryService::MicrosoftAD": "Name",
	"AWS::DirectoryService::SimpleAD": "Name",
	"AWS::DMS::Endpoint": "",
	"AWS::DynamoDB::Table": "TableName",
	"AWS::EC2::Volume": "",
	"AWS::EC2::NetworkAclEntry": "",
	"AWS::EC2::Subnet": "",
	"AWS::ECR::Repository": "RepositoryName",
	"AWS::ECS::Service": "ServiceName",
	"AWS::ECS::TaskDefinition": "",
	"AWS::EFS::FileSystem": "",
	"AWS::EKS::Nodegroup": "NodegroupName",
	"AWS::Elasticsearch::Domain": "DomainName",
	"AWS::ElastiCache::CacheCluster": "ClusterName",
	"AWS::ElastiCache::ReplicationGroup": "",
	"AWS::EMR::Cluster": "Name",
	"AWS::EMR::SecurityConfiguration": "Name",
	"AWS::EC2::SecurityGroupIngress": "GroupName",
	"AWS::ECS::Cluster": "ClusterName",
	"AWS::GameLift::Fleet": "Name",
	"AWS::CodeStar::GitHubRepository": "RepositoryName",
	"AWS::GuardDuty::Detector": "",
	"AWS::Lambda::Function": "FunctionName",
	"AWS::IAM::Group": "GroupName",
	"AWS::IAM::ManagedPolicy": "ManagedPolicyName",
	"AWS::IAM::User": "UserName",
	"AWS::IAM::Policy": "PolicyName",
	"AWS::IAM::AccessKey": "",
	"AWS::IoT::Policy": "PolicyName",
	"AWS::Kinesis::Stream": "Name",
	"AWS::Lambda::Permission": "",
	"AWS::MSK::Cluster": "ClusterName",
	"AWS::EC2::Route": "",
	"AWS::S3::Bucket": "BucketName",
	"AWS::S3::BucketPolicy": "",
	"AWS::SageMaker::NotebookInstance": "NotebookInstanceName",
	"AWS::SageMaker::EndpointConfig": "EndpointConfigName",
	"AWS::SDB::Domain": "",
	"AWS::SecretsManager::Secret": "Name",
	"AWS::EC2::SecurityGroupEgress": "",
	"AWS::GlobalAccelerator::Accelerator": "Name",
	"AWS::EC2::EIP": "",
	"AWS::SNS::TopicPolicy": "",
	"AWS::SNS::Topic": "TopicName",
	"AWS::SQS::QueuePolicy": "",
	"AWS::SQS::Queue": "QueueName",
	"AWS::CloudFormation::Stack": "",
	"AWS::CloudFormation::StackSet": "StackSetName",
	"AWS::AutoScaling::LaunchConfiguration": "LaunchConfigurationName",
	"AWS::EC2::VPC": "",
	"AWS::EC2::VPCGatewayAttachment": "",
	"AWS::EC2::FlowLog": "",
	"AWS::NetworkFirewall::Firewall": "FirewallName",
	"AWS::WAF::WebACL": "Name",
	"AWS::CertificateManager::Certificate": "",
	"AWS::Serverless::HttpApi": "",
	"AWS::Serverless::Api": "",
	"AWS::Serverless::Function": "FunctionName",
}

pseudo_parameter_default_replacements = {
	"${AWS::AccountId}":   "aws-account-id",
	"${AWS::NotificationARNs}": "aws-notification-arns",
	"${AWS::NoValue}":     "aws-no-value",
	"${AWS::Partition}":   "aws",
	"${AWS::Region}":      "aws-region",
	"${AWS::StackId}":     "aws-stack-id",
	"${AWS::StackName}":   "aws-stack-name",
	"${AWS::URLSuffix}":   "amazonaws.com",
}

parameter_default_replacements = replacements {
	params := input.document[_].Parameters
	replacements := {old: new |
		some param_name
		param := params[param_name]
		param.Default != null
		old := sprintf("${%s}", [param_name])
		new := sprintf("%v", [param.Default])
	}
} else = replacements {
	replacements := {}
}

sub_template(sub_expr) = template {
	is_string(sub_expr)
	template := sub_expr
} else = template {
	is_array(sub_expr)
	count(sub_expr) > 0
	is_string(sub_expr[0])
	template := sub_expr[0]
}

intrinsic_value_to_string(v) = stringified {
	is_string(v)
	stringified := v
} else = stringified {
	is_number(v)
	stringified := sprintf("%v", [v])
} else = stringified {
	is_boolean(v)
	stringified := sprintf("%v", [v])
} else = stringified {
	common_lib.valid_key(v, "Ref")
	ref_name := v.Ref
	stringified := input.document[_].Parameters[ref_name].Default
	stringified != null
} else = stringified {
	common_lib.valid_key(v, "Ref")
	ref_name := v.Ref
	old := sprintf("${%s}", [ref_name])
	stringified := pseudo_parameter_default_replacements[old]
}

sequence_sub_replacements(sub_expr) = replacements {
	is_array(sub_expr)
	count(sub_expr) > 1
	vars := sub_expr[1]
	is_object(vars)
	replacements := {old: new |
		some var_name
		raw := vars[var_name]
		new := intrinsic_value_to_string(raw)
		old := sprintf("${%s}", [var_name])
	}
} else = replacements {
	replacements := {}
}

resolve_sub_name(sub_expr) = resolved {
	template := sub_template(sub_expr)
	step1 := strings.replace_n(parameter_default_replacements, template)
	step2 := strings.replace_n(pseudo_parameter_default_replacements, step1)
	resolved := strings.replace_n(sequence_sub_replacements(sub_expr), step2)
	not contains(resolved, "${")
	resolved != ""
}

get_resource_name(resource, resourceDefinitionName) = name {
	field := resourceFieldName[resource.Type]
	fieldValue := resource.Properties[field]
	is_string(fieldValue)
	fieldValue != ""
	name := fieldValue
} else = name {
	field := resourceFieldName[resource.Type]
	fieldValue := resource.Properties[field]
	is_string(fieldValue)
	fieldValue != ""
	name := fieldValue[_]
} else = name {
	field := resourceFieldName[resource.Type]
	sub_expr := resource.Properties[field]["Fn::Sub"]
	name := resolve_sub_name(sub_expr)
} else = name {
	field := resourceFieldName[resource.Type]
	ref_name := resource.Properties[field].Ref
	name := input.document[_].Parameters[ref_name].Default
	name != null
	name != ""
} else = name {
	field := resourceFieldName[resource.Type]
	ref_name := resource.Properties[field].Ref
	old := sprintf("${%s}", [ref_name])
	name := pseudo_parameter_default_replacements[old]
} else = name {
	name := common_lib.get_tag_name_if_exists(resource)
} else = name {
	name := resourceDefinitionName
}

getPath(path) = result {
	count(path) > 0
	path_string := common_lib.concat_path(path)
	out := array.concat([path_string], ["."])
	result := concat("", out)
} else = result {
	count(path) == 0
	result := ""
}

createSearchKey(elem) = search {
	not elem.Name.Ref
	search := sprintf("=%s", [elem.Name])
} else = search {
	elem.Name.Ref
	search := sprintf(".Ref=%s", [elem.Name.Ref])
}
