package Cx

import data.generic.ansible as ansLib

canonical := "config_aggregator"

fields := ["account_sources", "organization_source"]

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	configAggregator := task[variant]
	ansLib.checkState(configAggregator)

	not ansLib.isAnsibleTrue(configAggregator[fields[f]].all_aws_regions)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(configAggregator, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.%s.all_aws_regions", [task.name, variant, fields[f]]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'aws_config_aggregator.%s' should have all_aws_regions set to true", [fields[f]]),
		"keyActualValue": sprintf("'aws_config_aggregator.%s' has all_aws_regions set to false", [fields[f]]),
	}
}
