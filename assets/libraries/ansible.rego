package generic.ansible

# Global variable with all tasks in input
tasks := TasksPerDocument

# Builds an object that stores all tasks for each document id
TasksPerDocument[id] = result {
	document := input.document[i]
	id := document.id
	result := getTasks(document)
}

# Function used to get all tasks from a document
getTasks(document) = result {
	document.playbooks[0].tasks
	result := [task |
		playbook := document.playbooks[0].tasks[_]
		task := getTasksFromBlocks(playbook)[_]
	]
} else = result {
	result := [task |
		playbook := document.playbooks[_]
		task := getTasksFromBlocks(playbook)[_]
	]
}

# Function used to get all nested tasks inside a block task ("block", "always", "rescue")
getTasksFromBlocks(playbook) = result {
	playbook.block
	result := [task |
		walk(playbook, [path, task])
		is_object(task)
		not task.block
		validPath(path)
	]
} else = [playbook] {
	true
}

# Validates the path of a nested element inside a block task to assure it's a task
validPath(path) {
	count(path) > 1
	validGroup(path[minus(count(path), 2)])
}

# Identifies a block task
validGroup("block") = true

validGroup("always") = true

validGroup("rescue") = true

# Checks if a task is not an absent task
checkState(task) {
	state := object.get(task, "state", "undefined")
	state != "absent"
}

# Checks if a variable has 'true' value in Ansible
isAnsibleTrue(answer) {
	lower(answer) == "yes"
} else {
	lower(answer) == "true"
} else {
	answer == true
}

# Checks if a variable has 'false' value in Ansible
isAnsibleFalse(answer) {
	lower(answer) == "no"
} else {
	lower(answer) == "false"
} else {
	answer == false
}

check_database_flags_content(database_flags, flagName, flagValue) {
	database_flags[x].name == flagName
	database_flags[x].value != flagValue
}

check_database_flags_content(database_flags, flagName, flagValue) {
	database_flags.name == flagName
	database_flags.value != flagValue
}

allowsPort(allowed, port) {
	portNumber := to_number(port)
	some i
	contains(allowed.ports[i], "-")
	port_bounds := split(allowed.ports[i], "-")
	low := to_number(port_bounds[0])
	high := to_number(port_bounds[1])

	low <= portNumber
	high >= portNumber
} else {
	allowed.ports[_] == port
} else = false {
	true
}

# Checks if a given port is included in a network rule
isPortInRule(rule, portNumber) {
	rule.from_port != -1
	rule.from_port <= portNumber
	rule.to_port >= portNumber
}

isPortInRule(rule, portNumber) {
	rule.ports == portNumber
}

isPortInRule(rule, portNumber) {
	rule.ports[_] == portNumber
}

isPortInRule(rule, portNumber) {
	mports := split(rule.ports, "-")
	to_number(mports[0]) <= portNumber
	to_number(mports[1]) >= portNumber
}

isPortInRule(rule, portNumber) {
	mports := split(rule.ports[_], "-")
	to_number(mports[0]) <= portNumber
	to_number(mports[1]) >= portNumber
}

isPortInRule(rule, portNumber) {
	rule.from_port == -1
}

isPortInRule(rule, portNumber) {
	rule.to_port == -1
}

# Checks if CIDR represents entire network
isEntireNetwork(cidr) {
	is_array(cidr)
	cidrs = {"0.0.0.0/0", "::/0"}
	count({x | cidr[x]; cidr[x] == cidrs[j]}) != 0
}

isEntireNetwork(cidr) {
	is_string(cidr)
	cidrs = {"0.0.0.0/0", "::/0"}
	cidr == cidrs[j]
}

# ansible_modules: canonical -> { variants, name_key }
ansible_modules := {
	"acm_certificate": {"variants": {"community.aws.acm_certificate", "acm_certificate", "community.aws.aws_acm", "aws_acm"}, "name_key": "name_tag"},
	"ansible_config": {"variants": {"ansible_config"}, "name_key": "name"},
	"ansible_inventory": {"variants": {"ansible_inventory"}, "name_key": "name"},
	"ansible_playbook": {"variants": {"ansible_playbook"}, "name_key": "name"},
	"ansible_task": {"variants": {"ansible_task"}, "name_key": "become_user"},
	"api_gateway": {"variants": {"community.aws.api_gateway", "api_gateway", "community.aws.aws_api_gateway", "aws_api_gateway"}, "name_key": "name"},
	"apk": {"variants": {"community.general.apk", "apk"}, "name_key": "name"},
	"apt": {"variants": {"ansible.builtin.apt", "apt"}, "name_key": "name"},
	"archive": {"variants": {"community.general.archive", "archive"}, "name_key": "dest"},
	"assemble": {"variants": {"ansible.builtin.assemble", "assemble"}, "name_key": "dest"},
	"autoscaling_group": {"variants": {"amazon.aws.autoscaling_group", "autoscaling_group", "community.aws.ec2_asg", "ec2_asg"}, "name_key": "name"},
	"autoscaling_launch_config": {"variants": {"community.aws.autoscaling_launch_config", "autoscaling_launch_config", "community.aws.ec2_lc", "ec2_lc"}, "name_key": "name"},
	"azure_rm_adserviceprincipal": {"variants": {"azure.azcollection.azure_rm_adserviceprincipal", "azure_rm_adserviceprincipal"}, "name_key": "display_name"},
	"azure_rm_aks": {"variants": {"azure.azcollection.azure_rm_aks", "azure_rm_aks"}, "name_key": "name"},
	"azure_rm_appgateway": {"variants": {"azure.azcollection.azure_rm_appgateway", "azure_rm_appgateway"}, "name_key": "name"},
	"azure_rm_containerregistry": {"variants": {"azure.azcollection.azure_rm_containerregistry", "azure_rm_containerregistry"}, "name_key": "name"},
	"azure_rm_cosmosdbaccount": {"variants": {"azure.azcollection.azure_rm_cosmosdbaccount", "azure_rm_cosmosdbaccount"}, "name_key": "name"},
	"azure_rm_keyvault": {"variants": {"azure.azcollection.azure_rm_keyvault", "azure_rm_keyvault"}, "name_key": "vault_name"},
	"azure_rm_lock": {"variants": {"azure.azcollection.azure_rm_lock", "azure_rm_lock"}, "name_key": "name"},
	"azure_rm_monitorlogprofile": {"variants": {"azure.azcollection.azure_rm_monitorlogprofile", "azure_rm_monitorlogprofile"}, "name_key": "name"},
	"azure_rm_mysqlserver": {"variants": {"azure.azcollection.azure_rm_mysqlserver", "azure_rm_mysqlserver"}, "name_key": "name"},
	"azure_rm_postgresqlconfiguration": {"variants": {"azure.azcollection.azure_rm_postgresqlconfiguration", "azure_rm_postgresqlconfiguration"}, "name_key": "name"},
	"azure_rm_postgresqlserver": {"variants": {"azure.azcollection.azure_rm_postgresqlserver", "azure_rm_postgresqlserver"}, "name_key": "name"},
	"azure_rm_rediscache": {"variants": {"azure.azcollection.azure_rm_rediscache", "azure_rm_rediscache"}, "name_key": "name"},
	"azure_rm_rediscachefirewallrule": {"variants": {"azure.azcollection.azure_rm_rediscachefirewallrule", "azure_rm_rediscachefirewallrule"}, "name_key": "name"},
	"azure_rm_roledefinition": {"variants": {"azure.azcollection.azure_rm_roledefinition", "azure_rm_roledefinition"}, "name_key": "name"},
	"azure_rm_securitygroup": {"variants": {"azure.azcollection.azure_rm_securitygroup", "azure_rm_securitygroup"}, "name_key": "name"},
	"azure_rm_sqlfirewallrule": {"variants": {"azure.azcollection.azure_rm_sqlfirewallrule", "azure_rm_sqlfirewallrule"}, "name_key": "name"},
	"azure_rm_sqlserver": {"variants": {"azure.azcollection.azure_rm_sqlserver", "azure_rm_sqlserver"}, "name_key": "name"},
	"azure_rm_storageaccount": {"variants": {"azure.azcollection.azure_rm_storageaccount", "azure_rm_storageaccount"}, "name_key": "name"},
	"azure_rm_storageblob": {"variants": {"azure.azcollection.azure_rm_storageblob", "azure_rm_storageblob"}, "name_key": "blob"},
	"azure_rm_subnet": {"variants": {"azure.azcollection.azure_rm_subnet", "azure_rm_subnet"}, "name_key": "name"},
	"azure_rm_virtualmachine": {"variants": {"azure.azcollection.azure_rm_virtualmachine", "azure_rm_virtualmachine"}, "name_key": "name"},
	"azure_rm_webapp": {"variants": {"azure.azcollection.azure_rm_webapp", "azure_rm_webapp"}, "name_key": "name"},
	"batch_job_definition": {"variants": {"community.aws.batch_job_definition", "batch_job_definition", "community.aws.aws_batch_job_definition", "aws_batch_job_definition"}, "name_key": "job_definition_name"},
	"blockinfile": {"variants": {"ansible.builtin.blockinfile", "blockinfile"}, "name_key": "path"},
	"bower": {"variants": {"community.general.bower", "bower"}, "name_key": "name"},
	"bundler": {"variants": {"community.general.bundler", "bundler"}, "name_key": "name"},
	"cloudformation": {"variants": {"amazon.aws.cloudformation", "cloudformation"}, "name_key": "stack_name"},
	"cloudformation_stack_set": {"variants": {"community.aws.cloudformation_stack_set", "cloudformation_stack_set"}, "name_key": "name"},
	"cloudfront_distribution": {"variants": {"community.aws.cloudfront_distribution", "cloudfront_distribution"}, "name_key": "caller_reference"},
	"cloudtrail": {"variants": {"amazon.aws.cloudtrail", "community.aws.cloudtrail", "cloudtrail"}, "name_key": "name"},
	"cloudwatchlogs_log_group": {"variants": {"amazon.aws.cloudwatchlogs_log_group", "community.aws.cloudwatchlogs_log_group", "cloudwatchlogs_log_group"}, "name_key": "log_group_name"},
	"codebuild_project": {"variants": {"community.aws.codebuild_project", "codebuild_project", "community.aws.aws_codebuild", "aws_codebuild"}, "name_key": "name"},
	"config_aggregator": {"variants": {"community.aws.config_aggregator", "config_aggregator", "community.aws.aws_config_aggregator", "aws_config_aggregator"}, "name_key": "name"},
	"config_rule": {"variants": {"community.aws.config_rule", "config_rule", "community.aws.aws_config_rule", "aws_config_rule"}, "name_key": "name"},
	"copy": {"variants": {"ansible.builtin.copy", "copy"}, "name_key": "dest"},
	"dnf": {"variants": {"ansible.builtin.dnf", "dnf"}, "name_key": "name"},
    "easy_install": {"variants": {"community.general.easy_install", "easy_install"}, "name_key": "name"},
    "ec2_ami": {"variants": {"amazon.aws.ec2_ami", "ec2_ami"}, "name_key": "name"},
    "ec2_group": {"variants": {"amazon.aws.ec2_security_group", "amazon.aws.ec2_group", "ec2_group"}, "name_key": "name"},
    "ec2_instance": {"variants": {"amazon.aws.ec2_instance", "community.aws.ec2_instance", "ec2_instance"}, "name_key": "name"},
    "ec2_launch_template": {"variants": {"amazon.aws.ec2_launch_template", "community.aws.ec2_launch_template", "ec2_launch_template"}, "name_key": "name"},
    "ec2_vol": {"variants": {"amazon.aws.ec2_vol", "ec2_vol"}, "name_key": "name"},
    "ec2_vpc_subnet": {"variants": {"amazon.aws.ec2_vpc_subnet", "ec2_vpc_subnet"}, "name_key": "cidr"},
    "ecs_ecr": {"variants": {"community.aws.ecs_ecr", "ecs_ecr"}, "name_key": "name"},
    "ecs_service": {"variants": {"community.aws.ecs_service", "ecs_service"}, "name_key": "name"},
    "ecs_taskdefinition": {"variants": {"community.aws.ecs_taskdefinition", "ecs_taskdefinition"}, "name_key": "family"},
    "efs": {"variants": {"community.aws.efs", "efs"}, "name_key": "name"},
    "elasticache": {"variants": {"community.aws.elasticache", "elasticache"}, "name_key": "name"},
	"elb_application_lb": {"variants": {"amazon.aws.elb_application_lb", "community.aws.elb_application_lb", "elb_application_lb"}, "name_key": "name"},
	"elb_network_lb": {"variants": {"community.aws.elb_network_lb", "elb_network_lb"}, "name_key": "name"},
	"file": {"variants": {"ansible.builtin.file", "file"}, "name_key": "path"},
	"gcp_bigquery_dataset": {"variants": {"google.cloud.gcp_bigquery_dataset", "gcp_bigquery_dataset"}, "name_key": "dataset_id"},
	"gcp_compute_disk": {"variants": {"google.cloud.gcp_compute_disk", "gcp_compute_disk"}, "name_key": "name"},
	"gcp_compute_firewall": {"variants": {"google.cloud.gcp_compute_firewall", "gcp_compute_firewall"}, "name_key": "name"},
	"gcp_compute_network": {"variants": {"google.cloud.gcp_compute_network", "gcp_compute_network"}, "name_key": "name"},
	"gcp_compute_instance": {"variants": {"google.cloud.gcp_compute_instance", "gcp_compute_instance"}, "name_key": "name"},
	"gcp_compute_ssl_policy": {"variants": {"google.cloud.gcp_compute_ssl_policy", "gcp_compute_ssl_policy"}, "name_key": "name"},
	"gcp_compute_subnetwork": {"variants": {"google.cloud.gcp_compute_subnetwork", "gcp_compute_subnetwork"}, "name_key": "name"},
	"gcp_container_cluster": {"variants": {"google.cloud.gcp_container_cluster", "gcp_container_cluster"}, "name_key": "name"},
	"gcp_container_node_pool": {"variants": {"google.cloud.gcp_container_node_pool", "gcp_container_node_pool"}, "name_key": "name"},
	"gcp_dns_managed_zone": {"variants": {"google.cloud.gcp_dns_managed_zone", "gcp_dns_managed_zone"}, "name_key": "name"},
	"gcp_kms_crypto_key": {"variants": {"google.cloud.gcp_kms_crypto_key", "gcp_kms_crypto_key"}, "name_key": "name"},
	"gcp_sql_instance": {"variants": {"google.cloud.gcp_sql_instance", "gcp_sql_instance"}, "name_key": "name"},
	"gcp_storage_bucket": {"variants": {"google.cloud.gcp_storage_bucket", "gcp_storage_bucket"}, "name_key": "name"},
	"gem": {"variants": {"community.general.gem", "gem"}, "name_key": "name"},
	"get_url": {"variants": {"ansible.builtin.get_url", "get_url"}, "name_key": "dest"},
	"homebrew": {"variants": {"community.general.homebrew", "homebrew"}, "name_key": "name"},
	"htpasswd": {"variants": {"community.general.htpasswd", "htpasswd"}, "name_key": "name"},
	"iam_access_key": {"variants": {"amazon.aws.iam_access_key", "community.aws.iam_access_key", "iam_access_key"}, "name_key": "user_name"},
	"iam_group": {"variants": {"amazon.aws.iam_group", "community.aws.iam_group", "iam_group"}, "name_key": "name"},
	"iam_managed_policy": {"variants": {"amazon.aws.iam_managed_policy", "community.aws.iam_managed_policy", "iam_managed_policy"}, "name_key": "name"},
	"iam_password_policy": {"variants": {"amazon.aws.iam_password_policy", "community.aws.iam_password_policy", "iam_password_policy"}, "name_key": "name"},
	"iam_policy": {"variants": {"amazon.aws.iam_policy", "community.aws.iam_policy", "iam_policy"}, "name_key": "policy_name"},
	"iam_role": {"variants": {"amazon.aws.iam_role", "community.aws.iam_role", "iam_role"}, "name_key": "name"},
	"iam_user": {"variants": {"amazon.aws.iam_user", "community.aws.iam_user", "iam_user"}, "name_key": "name"},
	"ini_file": {"variants": {"community.general.ini_file", "ini_file"}, "name_key": "path"},
	"jenkins_plugin": {"variants": {"community.general.jenkins_plugin", "jenkins_plugin"}, "name_key": "name"},
	"kinesis_stream": {"variants": {"community.aws.kinesis_stream", "kinesis_stream"}, "name_key": "name"},
	"kms_key": {"variants": {"amazon.aws.kms_key", "kms_key", "community.aws.aws_kms", "aws_kms"}, "name_key": "alias"},
	"lambda": {"variants": {"amazon.aws.lambda", "community.aws.lambda", "lambda"}, "name_key": "name"},
	"lambda_policy": {"variants": {"amazon.aws.lambda_policy", "community.aws.lambda_policy", "lambda_policy"}, "name_key": "function_name"},
	"lineinfile": {"variants": {"ansible.builtin.lineinfile", "lineinfile"}, "name_key": "path"},
	"npm": {"variants": {"community.general.npm", "npm"}, "name_key": "name"},
	"openbsd_pkg": {"variants": {"community.general.openbsd_pkg", "openbsd_pkg"}, "name_key": "name"},
	"opensearch": {"variants": {"community.aws.opensearch", "opensearch"}, "name_key": "domain_name"},
	"package": {"variants": {"ansible.builtin.package", "package"}, "name_key": "name"},
	"pacman": {"variants": {"community.general.pacman", "pacman"}, "name_key": "name"},
	"pear": {"variants": {"community.general.pear", "pear"}, "name_key": "name"},
	"pip": {"variants": {"ansible.builtin.pip", "pip"}, "name_key": "name"},
	"pkg5": {"variants": {"community.general.pkg5", "pkg5"}, "name_key": "name"},
	"pkgutil": {"variants": {"community.general.pkgutil", "pkgutil"}, "name_key": "name"},
	"portage": {"variants": {"community.general.portage", "portage"}, "name_key": "package"},
	"rds_instance": {"variants": {"amazon.aws.rds_instance", "community.aws.rds_instance", "rds_instance"}, "name_key": "db_instance_identifier"},
	"rds_subnet_group": {"variants": {"amazon.aws.rds_subnet_group", "community.aws.rds_subnet_group", "rds_subnet_group"}, "name_key": "name"},
	"redshift": {"variants": {"community.aws.redshift", "redshift"}, "name_key": "identifier"},
	"replace": {"variants": {"ansible.builtin.replace", "replace"}, "name_key": "path"},
	"route53": {"variants": {"amazon.aws.route53", "community.aws.route53", "route53"}, "name_key": "record"},
	"s3_bucket": {"variants": {"amazon.aws.s3_bucket", "s3_bucket"}, "name_key": "name"},
	"s3_cors": {"variants": {"community.aws.s3_cors", "s3_cors", "community.aws.aws_s3_cors", "aws_s3_cors"}, "name_key": "name"},
    "s3_object": {"variants": {"amazon.aws.s3_object", "s3_object", "amazon.aws.aws_s3", "aws_s3"}, "name_key": "object"},
    "ses_identity_policy": {"variants": {"community.aws.ses_identity_policy", "ses_identity_policy", "community.aws.aws_ses_identity_policy", "aws_ses_identity_policy"}, "name_key": "identity"},
    "slackpkg": {"variants": {"community.general.slackpkg", "slackpkg"}, "name_key": "name"},
    "sns_topic": {"variants": {"community.aws.sns_topic", "sns_topic"}, "name_key": "name"},
    "sorcery": {"variants": {"community.general.sorcery", "sorcery"}, "name_key": "name"},
    "sqs_queue": {"variants": {"community.aws.sqs_queue", "sqs_queue"}, "name_key": "name"},
    "sts_assume_role": {"variants": {"amazon.aws.sts_assume_role", "community.aws.sts_assume_role", "sts_assume_role"}, "name_key": "role_arn"},
    "swdepot": {"variants": {"community.general.swdepot", "swdepot"}, "name_key": "name"},
    "template": {"variants": {"ansible.builtin.template", "template"}, "name_key": "dest"},
	"uri": {"variants": {"ansible.builtin.uri", "uri"}, "name_key": "url"},
	"win_copy": {"variants": {"ansible.windows.win_copy", "win_copy"}, "name_key": "dest"},
	"win_template": {"variants": {"ansible.windows.win_template", "win_template"}, "name_key": "dest"},
    "user": {"variants": {"ansible.builtin.user", "user"}, "name_key": "name"},
    "win_chocolatey": {"variants": {"chocolatey.chocolatey.win_chocolatey", "win_chocolatey"}, "name_key": "name"},
    "yarn": {"variants": {"community.general.yarn", "yarn"}, "name_key": "name"},
    "yum": {"variants": {"ansible.builtin.yum", "yum"}, "name_key": "name"},
    "zypper": {"variants": {"community.general.zypper", "zypper"}, "name_key": "name"}
}

# Set of variant keys (FQCNs/short names) for a canonical; iterate with get_variants(canonical)[_]
get_variants(canonical) = ansible_modules[canonical].variants

# Resource name from task: module_args[name_key] or fallback to task.name
get_resource_name(module_args, canonical, task) = name {
	key := ansible_modules[canonical].name_key
	name := object.get(module_args, key, task.name)
}
