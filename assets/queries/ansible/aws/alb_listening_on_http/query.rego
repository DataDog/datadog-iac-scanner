package Cx

import data.generic.ansible as ansLib

canonical := "elb_application_lb"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	applicationLb := task[variant]
	ansLib.checkState(applicationLb)

	applicationLb.listeners[index].Protocol != "HTTPS"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(applicationLb, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.listeners.Protocol=%s", [task.name, variant, applicationLb.listeners[index].Protocol]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'aws_elb_application_lb' Protocol should be 'HTTP'",
		"keyActualValue": "'aws_elb_application_lb' Protocol it's not 'HTTP'",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	applicationLb := task[variant]
	ansLib.checkState(applicationLb)

	applicationLb.listeners[index]
	not MissingProtocol(applicationLb.listeners)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(applicationLb, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.listeners", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "'aws_elb_application_lb' Protocol should be 'HTTP'",
		"keyActualValue": "'aws_elb_application_lb' Protocol is missing",
	}
}

MissingProtocol(listeners) {
	listeners[_].Protocol
}
