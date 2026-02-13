package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

# Check for google_artifact_registry_repository_iam_member
CxPolicy[result] {
    resource := input.document[i].resource.google_artifact_registry_repository_iam_member[name]
    common_lib.valid_key(resource, "member")
    member := resource.member
    member == "allAuthenticatedUsers"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "google_artifact_registry_repository_iam_member",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("google_artifact_registry_repository_iam_member[{{%s}}].member", [name]),
        "searchLine": common_lib.build_search_line(["resource", "google_artifact_registry_repository_iam_member", name, "member"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "IAM member should not be a public principal",
        "keyActualValue": sprintf("Found public principal: %s", [member]),
        "remediation": json.marshal({
            "before": "member = \"allUsers\" or \"allAuthenticatedUsers\"",
            "after": "Use a non-public principal"
        }),
        "remediationType": "replacement"
    }
}

# Check for google_artifact_registry_repository_iam_member
CxPolicy[result] {
    resource := input.document[i].resource.google_artifact_registry_repository_iam_member[name]
    common_lib.valid_key(resource, "member")
    member := resource.member
    member == "allUsers"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "google_artifact_registry_repository_iam_member",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("google_artifact_registry_repository_iam_member[{{%s}}].member", [name]),
        "searchLine": common_lib.build_search_line(["resource", "google_artifact_registry_repository_iam_member", name, "member"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "IAM member should not be a public principal",
        "keyActualValue": sprintf("Found public principal: %s", [member])
    }
}

# Check for google_artifact_registry_repository_iam_binding
CxPolicy[result] {
    resource := input.document[i].resource.google_artifact_registry_repository_iam_binding[name]
    common_lib.valid_key(resource, "members")
    member := resource.members[_]
    member == "allAuthenticatedUsers"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "google_artifact_registry_repository_iam_binding",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("google_artifact_registry_repository_iam_binding[{{%s}}].members", [name]),
        "searchLine": common_lib.build_search_line(["resource", "google_artifact_registry_repository_iam_binding", name, "members"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "IAM binding should not include public principals",
        "keyActualValue": "Public principal found in members"
    }
}

# Check for google_artifact_registry_repository_iam_binding
CxPolicy[result] {
    resource := input.document[i].resource.google_artifact_registry_repository_iam_binding[name]
    common_lib.valid_key(resource, "members")
    member := resource.members[_]
    member == "allUsers"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "google_artifact_registry_repository_iam_binding",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("google_artifact_registry_repository_iam_binding[{{%s}}].members", [name]),
        "searchLine": common_lib.build_search_line(["resource", "google_artifact_registry_repository_iam_binding", name, "members"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "IAM binding should not include public principals",
        "keyActualValue": "Public principal found in members"
    }
}
