package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

CxPolicy[result] {
    resource := input.document[i].resource.aws_iam_account_password_policy[name]
    common_lib.valid_key(resource, "require_uppercase_characters")
    resource.require_uppercase_characters == false

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_iam_account_password_policy",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_iam_account_password_policy[{{%s}}].require_uppercase_characters", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_iam_account_password_policy", name, "require_uppercase_characters"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "aws_iam_account_password_policy.require_uppercase_characters should be true",
        "keyActualValue": "aws_iam_account_password_policy.require_uppercase_characters is false",
        "remediation": json.marshal({
            "before": "require_uppercase_characters = false",
            "after": "require_uppercase_characters = true"
        }),
        "remediationType": "replacement",
    }
}
