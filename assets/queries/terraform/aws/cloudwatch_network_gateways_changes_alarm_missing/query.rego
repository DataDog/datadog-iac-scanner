package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

expressionArr := [
	{
		"op": "=",
		"value": "CreateCustomerGateway",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "DeleteCustomerGateway",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "AttachInternetGateway",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "CreateInternetGateway",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "DeleteInternetGateway",
		"name": "$.eventName",
	},
	{
		"op": "=",
		"value": "DetachInternetGateway",
		"name": "$.eventName",
	},
]

# { ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }
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
		"keyExpectedValue": "aws_cloudwatch_log_metric_filter should have pattern { ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) } and be associated an aws_cloudwatch_metric_alarm",
		"keyActualValue": "aws_cloudwatch_log_metric_filter not filtering pattern { ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) } or not associated with any aws_cloudwatch_metric_alarm",
		"searchLine": common_lib.build_search_line([], []),
	}
}
