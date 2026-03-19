package Cx

import data.generic.ansible as ansLib

canonical := "cloudfront_distribution"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cloudfront := task[variant]
	ansLib.checkState(cloudfront)

	not cloudfront.web_acl_id

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cloudfront, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "cloudfront_distribution.web_acl_id should be defined",
		"keyActualValue": "cloudfront_distribution.web_acl_id is undefined",
	}
}
