package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

CxPolicy[result] {
    resource := input.document[i].resource.aws_lambda_permission[name]
    common_lib.valid_key(resource, "principal")
    resource.principal == "*"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_lambda_permission",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_lambda_permission[{{%s}}].principal", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_lambda_permission", name, "principal"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "aws_lambda_permission.principal should not be '*' (public access)",
        "keyActualValue": "aws_lambda_permission.principal is '*' (public access)",
    }
}
