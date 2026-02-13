package Cx

import data.generic.terraform as tf_lib

CxPolicy[result] {
	broker := input.document[i].resource.aws_mq_broker[name]
	logs := broker.logs

	engine := object.get(broker, "engine_type", "")
	categories := expected_categories(engine)
	expected_categories_text := concat(" and ", categories)

	some j
	type := categories[j]
	logs[type] == false

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_mq_broker",
		"resourceName": tf_lib.get_specific_resource_name(broker, "aws_mq_broker", name),
		"searchKey": sprintf("aws_mq_broker[%s].logs.%s", [name, type]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' logging should be set to true", [expected_categories_text]),
		"keyActualValue": sprintf("'%s' is set to false", [type]),
	}
}

CxPolicy[result] {
	broker := input.document[i].resource.aws_mq_broker[name]
	logs := broker.logs

	engine := object.get(broker, "engine_type", "")
	categories := expected_categories(engine)
	expected_categories_text := concat(" and ", categories)

	some j
	type := categories[j]
	not has_key(logs, type)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_mq_broker",
		"resourceName": tf_lib.get_specific_resource_name(broker, "aws_mq_broker", name),
		"searchKey": sprintf("aws_mq_broker[%s].logs", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("'%s' logging should be set to true", [expected_categories_text]),
		"keyActualValue": sprintf("'%s' is undefined", [expected_categories_text]),
	}
}

CxPolicy[result] {
	broker := input.document[i].resource.aws_mq_broker[name]
	engine := object.get(broker, "engine_type", "")
	categories := expected_categories(engine)
	expected_categories_text := concat(" and ", categories)

	not broker.logs

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_mq_broker",
		"resourceName": tf_lib.get_specific_resource_name(broker, "aws_mq_broker", name),
		"searchKey": sprintf("aws_mq_broker[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("'logs' should be set and enabling %s logging", [expected_categories_text]),
		"keyActualValue": "'logs' is undefined",
	}
}

has_key(obj, key) {
	_ = obj[key]
}

expected_categories(engine) = cats {
	engine == "RabbitMQ"
	cats := ["general"]
}

expected_categories(engine) = cats {
	engine != "RabbitMQ"
	cats := ["general", "audit"]
}
