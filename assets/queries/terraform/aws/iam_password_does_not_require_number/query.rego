package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

CxPolicy[result] {
    resource := input.document[i].resource.aws_iam_account_password_policy[name]
    common_lib.valid_key(resource, "require_numbers")
    resource.require_numbers == false

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_iam_account_password_policy",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_iam_account_password_policy[{{%s}}].require_numbers", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_iam_account_password_policy", name, "require_numbers"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "aws_iam_account_password_policy.require_numbers should be true",
        "keyActualValue": "aws_iam_account_password_policy.require_numbers is false",
        "remediation": json.marshal({
            "before": "require_numbers = false",
            "after": "require_numbers = true"
        }),
        "remediationType": "replacement",
    }
}
