package Cx

import data.generic.ansible as ansLib

canonical := "lambda_policy"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	lambdaPolicy := task[variant]
	ansLib.checkState(lambdaPolicy)

	lambdaAction(lambdaPolicy.action)
	principalAllowAPIGateway(lambdaPolicy.principal)
	re_match("/\\*/\\*$", lambdaPolicy.source_arn)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(lambdaPolicy, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.source_arn", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "lambda_policy.source_arn should not equal to '/*/*'",
		"keyActualValue": "lambda_policy.source_arn is equal to '/*/*'",
	}
}

lambdaAction("lambda:*") = true

lambdaAction("lambda:InvokeFunction") = true

principalAllowAPIGateway("*") = true

principalAllowAPIGateway("apigateway.amazonaws.com") = true
