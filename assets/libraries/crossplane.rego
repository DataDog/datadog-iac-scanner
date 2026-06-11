package generic.crossplane

import rego.v1

import data.generic.common as common_lib

getPath(path) := result if {
	count(path) > 0
	path_string := common_lib.concat_path(path)
	out := array.concat([path_string], ["."])
	result := concat("", out)
} else := result if {
	count(path) == 0
	result := ""
}

getResourceName(resource) := name if {
	resourceNameAtt := crossplaneResourcesWithName[resource.Kind]
	forProvider := resource.spec.forProvider
	name := forProvider[resourceNameAtt]
} else := name if {
	name := common_lib.get_tag_name_if_exists(resource)
} else := name if {
	name := resource.metadata.name
}

crossplaneResourcesWithName := {
	"Redis": "resourceGroupName",
	"AKSCluster": "resourceGroupName",
	"DBCluster": "databaseName",
	"SecurityGroup": "groupName",
}
