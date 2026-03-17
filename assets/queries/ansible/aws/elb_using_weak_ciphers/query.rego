package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

# elb_network_lb
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	canonical := "elb_network_lb"
	variant := ansLib.get_variants(canonical)[_]
	elb := task[variant]
	ansLib.checkState(elb)

	not common_lib.valid_key(elb, "listeners")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(elb, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("%s.listeners should be defined", [variant]),
		"keyActualValue": sprintf("%s.listeners is undefined", [variant]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	canonical := "elb_network_lb"
	variant := ansLib.get_variants(canonical)[_]
	elb := task[variant]
	ansLib.checkState(elb)

	listener := elb.listeners[j]
	not common_lib.valid_key(listener, "SslPolicy")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(elb, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.listeners.%s", [task.name, variant, j]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("%s.listeners.SslPolicy should be defined", [variant]),
		"keyActualValue": sprintf("%s.listeners.SslPolicy is undefined", [variant]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	canonical := "elb_network_lb"
	variant := ansLib.get_variants(canonical)[_]
	elb := task[variant]
	ansLib.checkState(elb)

	common_lib.weakCipher(elb.listeners[j].SslPolicy)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(elb, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.listeners.%s", [task.name, variant, j]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s.listeners.SslPolicy should not be a weak cipher", [variant]),
		"keyActualValue": sprintf("%s.listeners.SslPolicy is a weak cipher", [variant]),
	}
}

# elb_application_lb
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	canonical := "elb_application_lb"
	variant := ansLib.get_variants(canonical)[_]
	elb := task[variant]
	ansLib.checkState(elb)

	not common_lib.valid_key(elb, "listeners")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(elb, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("%s.listeners should be defined", [variant]),
		"keyActualValue": sprintf("%s.listeners is undefined", [variant]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	canonical := "elb_application_lb"
	variant := ansLib.get_variants(canonical)[_]
	elb := task[variant]
	ansLib.checkState(elb)

	listener := elb.listeners[j]
	not common_lib.valid_key(listener, "SslPolicy")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(elb, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.listeners.%s", [task.name, variant, j]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("%s.listeners.SslPolicy should be defined", [variant]),
		"keyActualValue": sprintf("%s.listeners.SslPolicy is undefined", [variant]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	canonical := "elb_application_lb"
	variant := ansLib.get_variants(canonical)[_]
	elb := task[variant]
	ansLib.checkState(elb)

	common_lib.weakCipher(elb.listeners[j].SslPolicy)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(elb, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.listeners.%s", [task.name, variant, j]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s.listeners.SslPolicy should not be a weak cipher", [variant]),
		"keyActualValue": sprintf("%s.listeners.SslPolicy is a weak cipher", [variant]),
	}
}
