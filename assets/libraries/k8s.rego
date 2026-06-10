package generic.k8s

import rego.v1

import data.generic.common as common_lib

getSpecInfo(document) := specInfo if { # this one can be also used for the result
	templates := {"job_template", "jobTemplate"}
	spec := document.spec[templates[t]].spec.template.spec
	specInfo := {"spec": spec, "path": sprintf("spec.%s.spec.template.spec", [templates[t]])}
} else := specInfo if {
	spec := document.spec.template.spec
	specInfo := {"spec": spec, "path": "spec.template.spec"}
} else := specInfo if {
	spec := document.spec
	specInfo := {"spec": spec, "path": "spec"}
}

checkKind(currentKind, listKinds) if {
	currentKind == listKinds[i]
}

checkKindWithKnative(doc, listKinds, knativeKinds) if {
	doc.kind == listKinds[i]
} else if {
	contains(doc.apiVersion, "knative")
	doc.kind == knativeKinds[i]
}

hasFlag(container, flag) if {
	common_lib.inArray(container.command, flag)
} else if {
	common_lib.inArray(container.args, flag)
}

startWithFlag(container, flag) if {
	startsWithArray(container.command, flag)
} else if {
	startsWithArray(container.args, flag)
}

startsWithArray(arr, item) if {
	startswith(arr[_], item)
}

hasFlagWithValue(container, flag, value) if {
	command := container.command
	startswith(command[a], flag)
	values := split(command[a], "=")[1]
	hasValue(values, value)
} else if {
	args := container.args
	startswith(args[a], flag)
	values := split(args[a], "=")[1]
	hasValue(values, value)
}

hasValue(values, value) if {
	splittedValues := split(values, ",")
	splittedValues[_] == value
}

startAndEndWithFlag(container, flag, ext) if {
	startWithAndEndWithArray(container.command, flag, ext)
} else if {
	startWithAndEndWithArray(container.args, flag, ext)
}

startWithAndEndWithArray(arr, item, ext) if {
	startswith(arr[_], item)
	endswith(arr[_], ext)
}

hasFlagEqualOrGreaterThanValue(container, flag, value) if {
	command := container.command
	startswith(command[a], flag)
	flag_value := split(command[a], "=")[1]
	to_number(flag_value) >= value
} else if {
	args := container.args
	startswith(args[a], flag)
	flag_value := split(args[a], "=")[1]
	to_number(flag_value) >= value
}

hasFlagBetweenValues(container, flag, higher, lower) if {
	command := container.command
	startswith(command[a], flag)
	value := split(command[a], "=")[1]
	betweenValues(value, higher, lower)
} else if {
	args := container.args
	startswith(args[a], flag)
	value := split(args[a], "=")[1]
	betweenValues(value, higher, lower)
}

betweenValues(value, higher, lower) if {
	to_number(value) > higher
	to_number(value) < lower
}

# Valid K8s/Knative Kinds that support podSpec or PodSpecTemplate
# https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.19/#podspec-v1-core
valid_pod_spec_kind_list := [
	"Pod",
	"Configuration",
	"Service",
	"Revision",
	"ContainerSource",
]
