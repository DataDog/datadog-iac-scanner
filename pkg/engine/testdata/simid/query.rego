package datadog

# Minimal rule for TestInspectorSimilarityID: fires on every aws_instance resource.
# Deliberately avoids library imports so it works with the stubQueriesSource library stub.
DatadogPolicy[result] {
	resource := input.document[i].resource.aws_instance[name]
	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_instance",
		"resourceName": name,
		"searchKey": sprintf("aws_instance[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "aws_instance should not be used",
		"keyActualValue": "aws_instance is present",
	}
}
