package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

# Rule for azurerm_network_security_group resources
CxPolicy[result] {
    resource := input.document[i].resource.azurerm_network_security_group[name]
    common_lib.valid_key(resource, "security_rule")
    rules := common_lib.as_array(resource.security_rule)
    rule := rules[_]

    common_lib.valid_key(rule, "protocol")
    lower(rule.protocol) == "udp"
    common_lib.valid_key(rule, "direction")
    lower(rule.direction) == "inbound"
    common_lib.valid_key(rule, "access")
    lower(rule.access) == "allow"
    common_lib.valid_key(rule, "source_address_prefix")
    lower(rule.source_address_prefix) == "0.0.0.0/0"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "azurerm_network_security_group",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("azurerm_network_security_group[{{%s}}].security_rule", [name]),
        "searchLine": common_lib.build_search_line(["resource", "azurerm_network_security_group", name, "security_rule"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "NSG rules should not allow UDP inbound access from the public Internet",
        "keyActualValue": "Rule permits UDP inbound access from public Internet"
    }
}

# Rule for azurerm_network_security_rule resources
CxPolicy[result] {
    resource := input.document[i].resource.azurerm_network_security_rule[name]

    common_lib.valid_key(resource, "protocol")
    lower(resource.protocol) == "udp"
    common_lib.valid_key(resource, "direction")
    lower(resource.direction) == "inbound"
    common_lib.valid_key(resource, "access")
    lower(resource.access) == "allow"
    common_lib.valid_key(resource, "source_address_prefix")
    lower(resource.source_address_prefix) == "0.0.0.0/0"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "azurerm_network_security_rule",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("azurerm_network_security_rule[{{%s}}].source_address_prefix", [name]),
        "searchLine": common_lib.build_search_line(["resource", "azurerm_network_security_rule", name, "source_address_prefix"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "NSG rules should not allow UDP inbound access from the public Internet",
        "keyActualValue": "Rule permits UDP inbound access from public Internet"
    }
}
