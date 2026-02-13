package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

CxPolicy[result] {
    resource := input.document[i].resource.aws_iam_account_password_policy[name]
    common_lib.valid_key(resource, "require_lowercase_characters")
    resource.require_lowercase_characters == false

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_iam_account_password_policy",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_iam_account_password_policy[{{%s}}].require_lowercase_characters", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_iam_account_password_policy", name, "require_lowercase_characters"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "aws_iam_account_password_policy.require_lowercase_characters should be true",
        "keyActualValue": "aws_iam_account_password_policy.require_lowercase_characters is false",
        "remediation": json.marshal({
            "before": "require_lowercase_characters = false",
            "after": "require_lowercase_characters = true"
        }),
        "remediationType": "replacement",
    }
}
