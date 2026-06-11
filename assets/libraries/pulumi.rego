package generic.pulumi

import rego.v1

import data.generic.common as common_lib

getResourceName(resource, logicName) := name if {
	resourceNameAtt := pulumiResourcesWithName[resource.Type]
	name := resource.Properties[resourceNameAtt]
} else := name if {
	name := common_lib.get_tag_name_if_exists(resource)
} else := name if {
	name := logicName
}

pulumiResourcesWithName := {
	"gcp:storage:Bucket": "name",
	"gcp:compute:SSLPolicy": "name",
}
