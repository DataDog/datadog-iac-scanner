package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

CxPolicy[result] {
    resource := input.document[i].resource.azurerm_mysql_server[name]
    common_lib.valid_key(resource, "ssl_minimal_tls_version_enforced")
    tls := resource.ssl_minimal_tls_version_enforced[_]
    lower(tls) != "tls1_2"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "azurerm_mysql_server",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("azurerm_mysql_server[{{%s}}].ssl_minimal_tls_version_enforced", [name]),
        "searchLine": common_lib.build_search_line(["resource", "azurerm_mysql_server", name, "ssl_minimal_tls_version_enforced"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "ssl_minimal_tls_version_enforced should be 'TLS1_2'",
        "keyActualValue": sprintf("Found ssl_minimal_tls_version_enforced = %v", [tls]),
        "remediation": json.marshal({
            "before": sprintf("ssl_minimal_tls_version_enforced = %v", [tls]),
            "after": "ssl_minimal_tls_version_enforced = \"TLS1_2\""
        }),
        "remediationType": "replacement"
    }
}
