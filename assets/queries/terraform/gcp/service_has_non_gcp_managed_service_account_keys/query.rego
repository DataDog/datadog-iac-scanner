package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    resource := input.document[i].resource.google_service_account_key[name]
    common_lib.valid_key(resource, "public_key_data")
    result := {
        "documentId": input.document[i].id,
        "resourceType": "google_service_account_key",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("google_service_account_key[%s].public_key_data", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "google_service_account_key should not have a public_key_data attribute",
        "keyActualValue": "google_service_account_key has a public_key_data attribute",
        "searchLine": common_lib.build_search_line(["resource", "google_service_account_key", name],["public_key_data"]),
        "remediation": "Remove the google_service_account_key resource to rely only on GCP-managed keys.",
        "remediationType": "removal",
    }
}
