package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

CxPolicy[result] {
    resource := input.document[i].resource.aws_dms_endpoint[name]
    common_lib.valid_key(resource, "endpoint_type")
    common_lib.valid_key(resource, "engine_name")
    common_lib.valid_key(resource, "ssl_mode")

    resource.endpoint_type == "source"
    not resource.engine_name == "s3"
    not resource.engine_name == "azuredb"
    resource.ssl_mode == "none"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_dms_endpoint",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_dms_endpoint[{{%s}}].ssl_mode", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_dms_endpoint", name, "ssl_mode"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "aws_dms_endpoint.ssl_mode should not be 'none' for non-exempt source endpoints",
        "keyActualValue": sprintf("aws_dms_endpoint.ssl_mode is '%s'", [resource.ssl_mode]),
        "remediation": json.marshal({
            "before": "none",
            "after": "require"
        }),
        "remediationType": "replacement"
    }
}

CxPolicy[result] {
    resource := input.document[i].resource.aws_dms_endpoint[name]
    common_lib.valid_key(resource, "endpoint_type")
    common_lib.valid_key(resource, "engine_name")
    common_lib.valid_key(resource, "ssl_mode")

    resource.endpoint_type == "target"
    not resource.engine_name == "dynamodb"
    not resource.engine_name == "kinesis"
    not resource.engine_name == "neptune"
    not resource.engine_name == "redshift"
    not resource.engine_name == "s3"
    not resource.engine_name == "elasticsearch"
    not resource.engine_name == "kafka"
    resource.ssl_mode == "none"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_dms_endpoint",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_dms_endpoint[{{%s}}].ssl_mode", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_dms_endpoint", name, "ssl_mode"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "aws_dms_endpoint.ssl_mode should not be 'none' for non-exempt target endpoints",
        "keyActualValue": sprintf("aws_dms_endpoint.ssl_mode is '%s'", [resource.ssl_mode]),
        "remediation": json.marshal({
            "before": "none",
            "after": "require"
        }),
        "remediationType": "replacement"
    }
}
