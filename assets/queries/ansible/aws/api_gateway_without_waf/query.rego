package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

# wafv2_resources has no canonical mapping; keep as local set for cross-task check
wafVariants := {"community.aws.wafv2_resources", "wafv2_resources"}

canonical := "api_gateway"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	api := task[variant]
	ansLib.checkState(api)

	not has_waf_associated(api.stage)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(api, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "API Gateway Stage should be associated with a Web Application Firewall",
		"keyActualValue": "API Gateway Stage is not associated with a Web Application Firewall",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant], []),
	}
}

has_waf_associated(stage) {
	wafVariants[wv]
	task2 := ansLib.tasks[_][_]
	wafResource := task2[wv]
	ansLib.checkState(wafResource)
	contains(wafResource.arn, "arn:aws:apigateway:")
	associatedStage := split(wafResource.arn, "/")
	associatedStage[4] == stage
}
