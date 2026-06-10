package generic.cloudformation

import rego.v1

import data.generic.common as common_lib

normalize_cloudFormation_boolean(boolOrString) := string if {
	boolOrString == true
	string = "true"
} else := string if {
	lower(boolOrString) == "true"
	string = "true"
} else := string if {
	lower(boolOrString) == "on"
	string = "true"
} else := string if {
	lower(boolOrString) == "yes"
	string = "true"
} else := string if {
	string = "false"
}

# Find out if the document has a resource type equals to 'AWS::SecretsManager::Secret'
hasSecretManager(str, document) if {
	selectedSecret := strings.replace_n({"${": "", "}": ""}, regex.find_n(`\${\w+}`, str, 1)[0])
	document[selectedSecret].Type == "AWS::SecretsManager::Secret"
}

# Check if the type is ELB
isLoadBalancer(resource) if {
	resource.Type == "AWS::ElasticLoadBalancing::LoadBalancer"
}

# Check if the type is ELB
isLoadBalancer(resource) if {
	resource.Type == "AWS::ElasticLoadBalancingV2::LoadBalancer"
}

# Check if there is an action inside an array
checkAction(currentAction, actionToCompare) if {
	is_string(currentAction)
	currentAction == "*"
	currentAction == actionToCompare
} else if {
	is_string(currentAction)
	contains(lower(currentAction), actionToCompare)
} else if {
	is_array(currentAction)
	action := currentAction[_]
	action == "*"
	action == actionToCompare
} else if {
	is_array(currentAction)
	action := currentAction[_]
	contains(lower(action), actionToCompare)
}

# Dictionary of UDP ports
udpPortsMap := {
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
getResourcesByType(resources, type) := list if {
	list = [resource | resources[i].Type == type; resource := resources[i]]
}

getBucketName(resource) := name if {
	name := resource.Properties.Bucket
	not common_lib.valid_key(name, "Ref")
} else := name if {
	name := resource.Properties.Bucket.Ref
}

get_encryption(resource) := encryption if {
	resource.Properties.Encrypted == true
	encryption := "encrypted"
} else := encryption if {
	fields := {"EncryptionSpecification", "KmsMasterKeyId", "EncryptionInfo", "EncryptionOptions", "BucketEncryption", "StreamEncryption"}
	common_lib.valid_key(resource.Properties, fields[_])
	encryption := "encrypted"
} else := encryption if {
	encryption := "unencrypted"
}

get_name(targetName) := name if {
	common_lib.valid_key(targetName, "Ref")
	name := targetName.Ref
} else := name if {
	not common_lib.valid_key(targetName, "Ref")
	name := targetName
}

get_resource_accessibility(nameRef, type, key) := info if {
	document := input.document
	policy := document[_].Resources[_]
	policy.Type == type

	keys := policy.Properties[key]

	get_name(keys) == nameRef

	statement := common_lib.get_statement(policy.Properties.PolicyDocument)
	common_lib.any_principal(statement)
	common_lib.is_allow_effect(statement)

	info := {"accessibility": "public", "policy": policy.Properties.PolicyDocument}
} else := info if {
	document := input.document
	policy := document[_].Resources[_]
	policy.Type == type

	keys := policy.Properties[key]

	get_name(keys[_]) == nameRef

	statement := common_lib.get_statement(policy.Properties.PolicyDocument)
	common_lib.any_principal(statement)
	common_lib.is_allow_effect(statement)

	info := {"accessibility": "public", "policy": policy.Properties.PolicyDocument}
} else := info if {
	document := input.document
	policy := document[_].Resources[_]
	policy.Type == type

	keys := policy.Properties[key]

	get_name(keys) == nameRef

	info := {"accessibility": "hasPolicy", "policy": policy.Properties.PolicyDocument}
} else := info if {
	document := input.document
	policy := document[_].Resources[_]
	policy.Type == type

	keys := policy.Properties[key]

	get_name(keys[_]) == nameRef

	info := {"accessibility": "hasPolicy", "policy": policy.Properties.PolicyDocument}
} else := info if {
	info := {"accessibility": "unknown", "policy": ""}
}

resourceFieldName := {
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

pseudo_parameter_default_replacements := {
	"${AWS::AccountId}": "aws-account-id",
	"${AWS::NotificationARNs}": "aws-notification-arns",
	"${AWS::NoValue}": "aws-no-value",
	"${AWS::Partition}": "aws",
	"${AWS::Region}": "aws-region",
	"${AWS::StackId}": "aws-stack-id",
	"${AWS::StackName}": "aws-stack-name",
	"${AWS::URLSuffix}": "amazonaws.com",
}

parameter_default_replacements := replacements if {
	params := input.document[_].Parameters
	replacements := {old: new |
		some param_name
		param := params[param_name]
		param.Default != null
		old := sprintf("${%s}", [param_name])
		new := sprintf("%v", [param.Default])
	}
} else := replacements if {
	replacements := {}
}

# sub_template extracts the template string from an Fn::Sub value.
# Fn::Sub has two shapes:
#   - string form:   "my-app-${Env}"
#   - sequence form: ["my-app-${Env}", {"Env": "prod"}]
# In the sequence form the first element is the template and the second is a map
# of explicit variable bindings. When the template head is itself an intrinsic
# (e.g. {"Fn::If": [...]}) it is not a string, so no template is produced and
# callers fall back to the logical id.
sub_template(sub_expr) := template if {
	is_string(sub_expr)
	template := sub_expr
} else := template if {
	is_array(sub_expr)
	count(sub_expr) > 0
	is_string(sub_expr[0])
	template := sub_expr[0]
}

intrinsic_value_to_string(v) := stringified if {
	is_string(v)
	stringified := v
} else := stringified if {
	is_number(v)
	stringified := sprintf("%v", [v])
} else := stringified if {
	is_boolean(v)
	stringified := sprintf("%v", [v])
} else := stringified if {
	common_lib.valid_key(v, "Ref")
	ref_name := v.Ref
	default_val := input.document[_].Parameters[ref_name].Default
	default_val != null
	stringified := sprintf("%v", [default_val])
} else := stringified if {
	common_lib.valid_key(v, "Ref")
	ref_name := v.Ref
	old := sprintf("${%s}", [ref_name])
	stringified := pseudo_parameter_default_replacements[old]
}

# sequence_sub_replacements builds the {"${Var}": "value"} replacement map from
# the explicit variable bindings of a sequence-form Fn::Sub, i.e. the second
# element of ["template", {"Var": value}]. Values may be literals or a Ref to a
# parameter/pseudo-parameter, resolved via intrinsic_value_to_string.
sequence_sub_replacements(sub_expr) := replacements if {
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
} else := replacements if {
	replacements := {}
}

# resolve_sub_name resolves an Fn::Sub expression to a concrete name.
# Replacement precedence matches CloudFormation: explicit variable bindings from
# the sequence form win over template Parameters, which win over pseudo
# parameters. If any placeholder remains unresolved the rule fails so callers
# fall back to the logical id rather than leaking a "${...}" string.
resolve_sub_name(sub_expr) := resolved if {
	template := sub_template(sub_expr)
	step1 := strings.replace_n(sequence_sub_replacements(sub_expr), template)
	step2 := strings.replace_n(parameter_default_replacements, step1)
	resolved := strings.replace_n(pseudo_parameter_default_replacements, step2)
	not contains(resolved, "${")
	resolved != ""
}

get_resource_name(resource, resourceDefinitionName) := name if {
	field := resourceFieldName[resource.Type]
	fieldValue := resource.Properties[field]
	is_string(fieldValue)
	fieldValue != ""
	name := fieldValue
} else := name if {
	field := resourceFieldName[resource.Type]
	fieldValue := resource.Properties[field]
	is_string(fieldValue)
	fieldValue != ""
	name := fieldValue[_]
} else := name if {
	field := resourceFieldName[resource.Type]
	sub_expr := resource.Properties[field]["Fn::Sub"]
	name := resolve_sub_name(sub_expr)
} else := name if {
	field := resourceFieldName[resource.Type]
	ref_name := resource.Properties[field].Ref
	name := input.document[_].Parameters[ref_name].Default
	name != null
	name != ""
} else := name if {
	field := resourceFieldName[resource.Type]
	ref_name := resource.Properties[field].Ref
	old := sprintf("${%s}", [ref_name])
	name := pseudo_parameter_default_replacements[old]
} else := name if {
	name := common_lib.get_tag_name_if_exists(resource)
} else := name if {
	name := resourceDefinitionName
}

getPath(path) := result if {
	count(path) > 0
	path_string := common_lib.concat_path(path)
	out := array.concat([path_string], ["."])
	result := concat("", out)
} else := result if {
	count(path) == 0
	result := ""
}

createSearchKey(elem) := search if {
	not elem.Name.Ref
	search := sprintf("=%s", [elem.Name])
} else := search if {
	elem.Name.Ref
	search := sprintf(".Ref=%s", [elem.Name.Ref])
}
