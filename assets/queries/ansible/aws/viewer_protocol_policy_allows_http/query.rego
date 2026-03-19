package Cx

import data.generic.ansible as ansLib

canonical := "cloudfront_distribution"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cloudfront_distribution := task[variant]
	ansLib.checkState(cloudfront_distribution)
	fields := ["default_cache_behavior", "cache_behaviors"]

	cloudfront_distribution[fields[f]].viewer_protocol_policy == "allow-all"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cloudfront_distribution, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.%s.viewer_protocol_policy", [task.name, variant, fields[f]]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("cloudfront_distribution.%s.viewer_protocol_policy should be 'https-only' or 'redirect-to-https'", [fields[f]]),
		"keyActualValue": sprintf("cloudfront_distribution.%s.viewer_protocol_policy isn't 'https-only' or 'redirect-to-https'", [fields[f]]),
	}
}
