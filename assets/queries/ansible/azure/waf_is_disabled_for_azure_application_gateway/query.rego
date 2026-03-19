package Cx

import data.generic.ansible as ansLib

canonical := "azure_rm_appgateway"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	appgateway := task[variant]
	ansLib.checkState(appgateway)

	not startswith(appgateway.sku.tier, "waf")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(appgateway, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.sku.tier", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "azure_rm_appgateway.sku.tier should be 'waf' or 'waf_v2'",
		"keyActualValue": sprintf("azure_rm_appgateway.sku.tier is %s", [appgateway.sku.tier]),
	}
}
