package Cx

import data.generic.ansible as ans_lib
import data.generic.common as common_lib

canonical := "cloudfront_distribution"

CxPolicy[result] {
	task := ans_lib.tasks[id][t]
	variant := ans_lib.get_variants(canonical)[_]
	cloudfront := task[variant]

	ans_lib.checkState(cloudfront)
	not common_lib.valid_key(cloudfront, "viewer_certificate")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ans_lib.get_resource_name(cloudfront, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "cloudfront_distribution.viewer_certificate should be defined",
		"keyActualValue": "cloudfront_distribution.viewer_certificate is undefined",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant], []),
	}
}

CxPolicy[result] {
	task := ans_lib.tasks[id][t]
	variant := ans_lib.get_variants(canonical)[_]
	cloudfront := task[variant]

	ans_lib.checkState(cloudfront)
	protocol_version := cloudfront.viewer_certificate.minimum_protocol_version

	not common_lib.is_recommended_tls(protocol_version)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ans_lib.get_resource_name(cloudfront, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.viewer_certificate.minimum_protocol_version", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("name={{%s}}.{{%s}}.viewer_certificate.minimum_protocol_version' should be TLSv1.2_x", [task.name, variant]),
		"keyActualValue": sprintf("name={{%s}}.{{%s}}.viewer_certificate.minimum_protocol_version' is %s", [task.name, variant, protocol_version]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "viewer_certificate", "minimum_protocol_version"], []),
	}
}
