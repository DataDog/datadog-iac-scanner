package datadog

import rego.v1

DatadogPolicy contains result if {
	resource := input.document[i].resource.aws_elasticache_cluster[name]
	resource.engine != "redis"

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_elasticache_cluster",
		"resourceName": get_specific_resource_name(resource, "aws_elasticache_cluster", name),
		"searchKey": sprintf("resource.aws_elasticache_cluster[%s].engine", [name]),
	}
}

get_specific_resource_name(resource, resourceType, resourceDefinitionName) := name if {
	field := resourceFieldName[resourceType]
	name := resource[field]
} else := name if {
	name := get_resource_name(resource, resourceDefinitionName)
}

get_resource_name(resource, resourceDefinitionName) := name if {
	name := resource.name
} else := name if {
	name := resource.display_name
} else := name if {
	name := resource.metadata.name
} else := name if {
	prefix := resource.name_prefix
	name := sprintf("%s<unknown-sufix>", [prefix])
} else := name if {
	name := get_tag_name_if_exists(resource)
} else := name if {
	name := resourceDefinitionName
}

get_tag_name_if_exists(resource) := name if {
	name := resource.tags.Name
} else := name if {
	tag := resource.Properties.Tags[_]
	tag.Key == "Name"
	name := tag.Value
} else := name if {
	tag := resource.Properties.FileSystemTags[_]
	tag.Key == "Name"
	name := tag.Value
} else := name if {
	tag := resource.Properties.Tags[key]
	key == "Name"
	name := tag
} else := name if {
	tag := resource.spec.forProvider.tags[_]
	tag.key == "Name"
	name := tag.value
} else := name if {
	tag := resource.properties.tags[key]
	key == "Name"
	name := tag
}

resourceFieldName := {
	"google_bigquery_dataset": "friendly_name",
	"alicloud_actiontrail_trail": "trail_name",
	"alicloud_ros_stack": "stack_name",
	"alicloud_oss_bucket": "bucket",
	"aws_s3_bucket": "bucket",
	"aws_msk_cluster": "cluster_name",
	"aws_mq_broker": "broker_name",
	"aws_elasticache_cluster": "cluster_id",
}
