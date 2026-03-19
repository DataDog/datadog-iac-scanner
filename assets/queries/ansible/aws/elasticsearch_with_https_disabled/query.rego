package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "opensearch"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	elasticsearch := task[variant]
	ansLib.checkState(elasticsearch)

	elasticsearch.domain_endpoint_options.enforce_https == false

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(elasticsearch, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.domain_endpoint_options.enforce_https", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("name={{%s}}.{{%s}}.domain_endpoint_options.enforce_https should be set to 'true'", [task.name, variant]),
		"keyActualValue": sprintf("name={{%s}}.{{%s}}.domain_endpoint_options.enforce_https is set to 'false'", [task.name, variant]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "domain_endpoint_options", "enforce_https"], []),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	elasticsearch := task[variant]
	ansLib.checkState(elasticsearch)

	not common_lib.valid_key(elasticsearch.domain_endpoint_options, "enforce_https")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(elasticsearch, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.domain_endpoint_options", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("name={{%s}}.{{%s}}.domain_endpoint_options.enforce_https should be defined and set to 'true'", [task.name, variant]),
		"keyActualValue": sprintf("name={{%s}}.{{%s}}.domain_endpoint_options.enforce_https is not set", [task.name, variant]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "domain_endpoint_options"], []),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	elasticsearch := task[variant]
	ansLib.checkState(elasticsearch)

	not common_lib.valid_key(elasticsearch, "domain_endpoint_options")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(elasticsearch, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("name={{%s}}.{{%s}}.domain_endpoint_options.enforce_https should be defined and set to 'true'", [task.name, variant]),
		"keyActualValue": sprintf("name={{%s}}.{{%s}}.domain_endpoint_options.enforce_https is not set", [task.name, variant]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant], []),
	}
}
