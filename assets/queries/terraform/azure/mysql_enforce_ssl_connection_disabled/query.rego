package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

CxPolicy[result] {
    resource := input.document[i].resource.azurerm_mysql_server[name]
    common_lib.valid_key(resource, "ssl_enforcement_enabled")
    ssl_value := resource.ssl_enforcement_enabled[_]
    ssl_value != "ENABLED"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "azurerm_mysql_server",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("azurerm_mysql_server[{{%s}}].ssl_enforcement_enabled", [name]),
        "searchLine": common_lib.build_search_line(["resource", "azurerm_mysql_server", name, "ssl_enforcement_enabled"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "ssl_enforcement_enabled should be 'ENABLED'",
        "keyActualValue": sprintf("Found ssl_enforcement_enabled = %v", [ssl_value]),
        "remediation": json.marshal({
            "before": sprintf("ssl_enforcement_enabled = %v", [ssl_value]),
            "after": "ssl_enforcement_enabled = \"ENABLED\""
        }),
        "remediationType": "replacement"
    }
}
