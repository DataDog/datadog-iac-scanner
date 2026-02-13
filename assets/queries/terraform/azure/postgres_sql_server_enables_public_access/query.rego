package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

# Rule 1: Violation when the attribute exists but is not false.
CxPolicy[result] {
    resource := input.document[i].resource.azurerm_postgresql_server[name]
    common_lib.valid_key(resource, "public_network_access_enabled")
    access_enabled := resource.public_network_access_enabled[_]
    access_enabled != false

    result := {
        "documentId": input.document[i].id,
        "resourceType": "azurerm_postgresql_server",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("azurerm_postgresql_server[%s].public_network_access_enabled", [name]),
        "searchLine": common_lib.build_search_line(["resource", "azurerm_postgresql_server", name, "public_network_access_enabled"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "public_network_access_enabled should be false",
        "keyActualValue": sprintf("Found public_network_access_enabled = %v", [access_enabled]),
        "remediation": json.marshal({
            "before": sprintf("%v", [access_enabled]),
            "after": "false"
        }),
        "remediationType": "replacement",
    }
}

# Rule 2: Violation when the attribute is missing.
CxPolicy[result] {
    resource := input.document[i].resource.azurerm_postgresql_server[name]
    not common_lib.valid_key(resource, "public_network_access_enabled")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "azurerm_postgresql_server",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("azurerm_postgresql_server[%s]", [name]),
        "searchLine": common_lib.build_search_line(["resource", "azurerm_postgresql_server", name], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "public_network_access_enabled must be present and set to false",
        "keyActualValue": "public_network_access_enabled is missing",
        "remediation": "public_network_access_enabled = false",
		"remediationType": "addition"
    }
}
