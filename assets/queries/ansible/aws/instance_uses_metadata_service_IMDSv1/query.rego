package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

# ec2_instance: check metadata_options.http_tokens for ec2_instance module
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	canonical := "ec2_instance"
	variant := ansLib.get_variants(canonical)[_]
	resource := task[variant]
	ansLib.checkState(resource)

	is_metadata_service_enabled(resource)

	not common_lib.valid_key(resource, "metadata_options")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(resource, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("'%s.metadata_options' should be defined with 'http_tokens' field set to 'required'", [variant]),
		"keyActualValue": sprintf("'%s.metadata_options' is not defined", [variant]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	canonical := "ec2_instance"
	variant := ansLib.get_variants(canonical)[_]
	resource := task[variant]
	ansLib.checkState(resource)

	is_metadata_service_enabled(resource)

	common_lib.valid_key(resource, "metadata_options")
	common_lib.valid_key(resource.metadata_options, "http_tokens")
	not resource.metadata_options.http_tokens == "required"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(resource, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.metadata_options.http_tokens", [task.name, variant]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "metadata_options", "http_tokens"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s.metadata_options.http_tokens' should be defined to 'required'", [variant]),
		"keyActualValue": sprintf("'%s.metadata_options.http_tokens' is not defined to 'required'", [variant]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	canonical := "ec2_instance"
	variant := ansLib.get_variants(canonical)[_]
	resource := task[variant]
	ansLib.checkState(resource)

	is_metadata_service_enabled(resource)

	common_lib.valid_key(resource, "metadata_options")
	not common_lib.valid_key(resource.metadata_options, "http_tokens")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(resource, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.metadata_options", [task.name, variant]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "metadata_options"], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("'%s.metadata_options.http_tokens' should be defined to 'required'", [variant]),
		"keyActualValue": sprintf("'%s.metadata_options.http_tokens' is not defined", [variant]),
	}
}

# autoscaling_launch_config: same checks for launch config / ec2_lc
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	canonical := "autoscaling_launch_config"
	variant := ansLib.get_variants(canonical)[_]
	resource := task[variant]
	ansLib.checkState(resource)

	is_metadata_service_enabled(resource)

	not common_lib.valid_key(resource, "metadata_options")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(resource, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("'%s.metadata_options' should be defined with 'http_tokens' field set to 'required'", [variant]),
		"keyActualValue": sprintf("'%s.metadata_options' is not defined", [variant]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	canonical := "autoscaling_launch_config"
	variant := ansLib.get_variants(canonical)[_]
	resource := task[variant]
	ansLib.checkState(resource)

	is_metadata_service_enabled(resource)

	common_lib.valid_key(resource, "metadata_options")
	common_lib.valid_key(resource.metadata_options, "http_tokens")
	not resource.metadata_options.http_tokens == "required"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(resource, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.metadata_options.http_tokens", [task.name, variant]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "metadata_options", "http_tokens"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s.metadata_options.http_tokens' should be defined to 'required'", [variant]),
		"keyActualValue": sprintf("'%s.metadata_options.http_tokens' is not defined to 'required'", [variant]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	canonical := "autoscaling_launch_config"
	variant := ansLib.get_variants(canonical)[_]
	resource := task[variant]
	ansLib.checkState(resource)

	is_metadata_service_enabled(resource)

	common_lib.valid_key(resource, "metadata_options")
	not common_lib.valid_key(resource.metadata_options, "http_tokens")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(resource, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.metadata_options", [task.name, variant]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "metadata_options"], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("'%s.metadata_options.http_tokens' should be defined to 'required'", [variant]),
		"keyActualValue": sprintf("'%s.metadata_options.http_tokens' is not defined", [variant]),
	}
}

is_metadata_service_enabled(resource) {
	common_lib.valid_key(resource, "metadata_options")
	common_lib.valid_key(resource.metadata_options, "http_endpoint")
	resource.metadata_options.http_endpoint == "enabled"
}

is_metadata_service_enabled(resource) {
	not common_lib.valid_key(resource, "metadata_options")
}

is_metadata_service_enabled(resource) {
	common_lib.valid_key(resource, "metadata_options")
	not common_lib.valid_key(resource.metadata_options, "http_endpoint")
}
