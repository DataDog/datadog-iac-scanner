package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

# For google_bigquery_table_iam_member resources
CxPolicy[result] {
    resource := input.document[i].resource.google_bigquery_table_iam_member[name]
    common_lib.valid_key(resource, "member")
    member := resource.member
    member == "allUsers"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "google_bigquery_table_iam_member",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("google_bigquery_table_iam_member[{{%s}}].member", [name]),
        "searchLine": common_lib.build_search_line(["resource", "google_bigquery_table_iam_member", name, "member"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "IAM member should not be a public principal",
        "keyActualValue": sprintf("Found public principal: %s", [member])
    }
}

# For google_bigquery_table_iam_member resources
CxPolicy[result] {
    resource := input.document[i].resource.google_bigquery_table_iam_member[name]
    common_lib.valid_key(resource, "member")
    common_lib.valid_key(resource, "member")
    member := resource.member
    member == "allAuthenticatedUsers"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "google_bigquery_table_iam_member",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("google_bigquery_table_iam_member[{{%s}}].member", [name]),
        "searchLine": common_lib.build_search_line(["resource", "google_bigquery_table_iam_member", name, "member"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "IAM member should not be a public principal",
        "keyActualValue": sprintf("Found public principal: %s", [member])
    }
}

# For google_bigquery_table_iam_binding resources
CxPolicy[result] {
    resource := input.document[i].resource.google_bigquery_table_iam_binding[name]
    common_lib.valid_key(resource, "members")
    member := resource.members[_]
    member == "allUsers"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "google_bigquery_table_iam_binding",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("google_bigquery_table_iam_binding[{{%s}}].members", [name]),
        "searchLine": common_lib.build_search_line(["resource", "google_bigquery_table_iam_binding", name, "members"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "IAM binding should not include public principals",
        "keyActualValue": "Public principal found in members"
    }
}

# For google_bigquery_table_iam_binding resources
CxPolicy[result] {
    resource := input.document[i].resource.google_bigquery_table_iam_binding[name]
    common_lib.valid_key(resource, "members")
    member := resource.members[_]
    member == "allAuthenticatedUsers"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "google_bigquery_table_iam_binding",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("google_bigquery_table_iam_binding[{{%s}}].members", [name]),
        "searchLine": common_lib.build_search_line(["resource", "google_bigquery_table_iam_binding", name, "members"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "IAM binding should not include public principals",
        "keyActualValue": "Public principal found in members"
    }
}
