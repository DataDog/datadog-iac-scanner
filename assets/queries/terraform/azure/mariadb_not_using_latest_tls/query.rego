package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

# Violation if ssl_enforcement_enabled is missing or not "true"
CxPolicy[result] {
    resource := input.document[i].resource.azurerm_mariadb_server[name]
    common_lib.valid_key(resource, "ssl_enforcement_enabled")
    ssl_enf := resource.ssl_enforcement_enabled[_]
    lower(ssl_enf) != "true"
    result := {
        "documentId": input.document[i].id,
        "resourceType": "azurerm_mariadb_server",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("azurerm_mariadb_server[%s].ssl_enforcement_enabled", [name]),
        "searchLine": common_lib.build_search_line(["resource", "azurerm_mariadb_server", name, "ssl_enforcement_enabled"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "ssl_enforcement_enabled should be 'true'",
        "keyActualValue": sprintf("Found ssl_enforcement_enabled = %v", [ssl_enf]),
        "remediation": json.marshal({
            "before": sprintf("ssl_enforcement_enabled = %v", [ssl_enf]),
            "after": "ssl_enforcement_enabled = \"true\""
        }),
        "remediationType": "replacement"
    }
}

# Violation if ssl_enforcement_enabled is "true" but ssl_minimal_tls_version_enforced exists and is not "TLS1_2"
CxPolicy[result] {
    resource := input.document[i].resource.azurerm_mariadb_server[name]
    common_lib.valid_key(resource, "ssl_enforcement_enabled")
    ssl_enf := resource.ssl_enforcement_enabled[_]
    lower(ssl_enf) == "true"
    common_lib.valid_key(resource, "ssl_minimal_tls_version_enforced")
    tls := resource.ssl_minimal_tls_version_enforced[_]
    lower(tls) != "tls1_2"
    result := {
        "documentId": input.document[i].id,
        "resourceType": "azurerm_mariadb_server",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("azurerm_mariadb_server[%s].ssl_minimal_tls_version_enforced", [name]),
        "searchLine": common_lib.build_search_line(["resource", "azurerm_mariadb_server", name, "ssl_minimal_tls_version_enforced"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "ssl_minimal_tls_version_enforced should be 'TLS1_2' if present",
        "keyActualValue": sprintf("Found ssl_minimal_tls_version_enforced = %v", [tls]),
        "remediation": json.marshal({
            "before": sprintf("ssl_minimal_tls_version_enforced = %v", [tls]),
            "after": "ssl_minimal_tls_version_enforced = \"TLS1_2\""
        }),
        "remediationType": "replacement"
    }
}
