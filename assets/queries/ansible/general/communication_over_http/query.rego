package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "uri"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	builtin_uri := task[variant]
	ansLib.checkState(builtin_uri)

	url := builtin_uri.url
	startswith(url, "http://")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(builtin_uri, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.url", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "ansible.builtin.uri.url should be accessed via the HTTPS protocol",
		"keyActualValue": "ansible.builtin.uri.url is accessed via the HTTP protocol'",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "url"], []),
	}
}
