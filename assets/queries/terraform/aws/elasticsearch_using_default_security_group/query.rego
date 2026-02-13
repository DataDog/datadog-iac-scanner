package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

CxPolicy[result] {
    resource := input.document[i].resource.aws_elasticsearch_domain[name]
    count(resource.vpc_options.security_group_ids) == 0

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_elasticsearch_domain",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_elasticsearch_domain[{{%s}}].vpc_options.security_group_ids", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_elasticsearch_domain", name, "vpc_options.security_group_ids"], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "aws_elasticsearch_domain.vpc_options.security_group_ids should not be empty",
        "keyActualValue": "aws_elasticsearch_domain.vpc_options.security_group_ids is empty"
    }
}

CxPolicy[result] {
    resource := input.document[i].resource.aws_opensearch_domain[name]
    count(resource.vpc_options.security_group_ids) == 0

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_opensearch_domain",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_opensearch_domain[{{%s}}].vpc_options.security_group_ids", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_opensearch_domain", name, "vpc_options.security_group_ids"], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "aws_opensearch_domain.vpc_options.security_group_ids should not be empty",
        "keyActualValue": "aws_opensearch_domain.vpc_options.security_group_ids is empty"
    }
}
