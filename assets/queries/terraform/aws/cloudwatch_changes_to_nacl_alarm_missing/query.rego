package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

expressionArr := [
	{
		"op": "=",
		"value": "CreateNetworkAcl",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "CreateNetworkAclEntry",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "DeleteNetworkAcl",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "DeleteNetworkAclEntry",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "ReplaceNetworkAclEntry",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "ReplaceNetworkAclAssociation",
		"name": "$.eventName",
	},
]

check_selector(filter, value, op, name) {
	selector := common_lib.find_selector_by_value(filter, value)
	selector._op == op
	selector._selector == name
}

# { ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }
check_expression_missing(resName, filter, doc) {
	alarm := doc.resource.aws_cloudwatch_metric_alarm[name]
	contains(alarm.metric_name, resName)

	count({x | exp := expressionArr[n]; common_lib.check_selector(filter, exp.value, exp.op, exp.name) == false; x := exp}) == 0
}

CxPolicy[result] {
	doc := input.document[i]
	resource := doc.resource.aws_cloudwatch_log_metric_filter[resourceName]
	filter := common_lib.json_unmarshal(resource.pattern)
	not check_expression_missing(resourceName, filter, doc)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_cloudwatch_log_metric_filter",
		"resourceName": tf_lib.get_resource_name(resource, resourceName),
		"searchKey": sprintf("aws_cloudwatch_log_metric_filter[%s].pattern", [resourceName]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "aws_cloudwatch_log_metric_filter should have pattern { ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) } and be associated an aws_cloudwatch_metric_alarm",
		"keyActualValue": "aws_cloudwatch_log_metric_filter not filtering pattern { ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) } or not associated with any aws_cloudwatch_metric_alarm",
		"searchLine": common_lib.build_search_line([], []),
	}
}
