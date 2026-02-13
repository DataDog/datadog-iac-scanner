package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

# Rule for azurerm_app_service
CxPolicy[result] {
    resource := input.document[i].resource.azurerm_app_service[name]
    common_lib.valid_key(resource, "site_config")
    config := object.get(resource, "site_config", "undefined")
    common_lib.valid_key(config, "remote_debugging_enabled")
    debugging := config.remote_debugging_enabled[_]
    debugging

    result := {
        "documentId": input.document[i].id,
        "resourceType": "azurerm_app_service",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("azurerm_app_service[%s].site_config.remote_debugging_enabled", [name]),
        "searchLine": common_lib.build_search_line(["resource", "azurerm_app_service", name, "site_config", "remote_debugging_enabled"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "remote_debugging_enabled should be false",
        "keyActualValue": sprintf("Found remote_debugging_enabled = %v", [debugging]),
        "remediation": json.marshal({
            "before": sprintf("remote_debugging_enabled = %v", [debugging]),
            "after": "remote_debugging_enabled = false"
        }),
        "remediationType": "replacement"
    }
}

# Rule for azurerm_linux_function_app
CxPolicy[result] {
    resource := input.document[i].resource.azurerm_linux_function_app[name]
    common_lib.valid_key(resource, "site_config")
    config := object.get(resource, "site_config", "undefined")
    common_lib.valid_key(config, "remote_debugging_enabled")
    debugging := config.remote_debugging_enabled[_]
    debugging

    result := {
        "documentId": input.document[i].id,
        "resourceType": "azurerm_linux_function_app",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("azurerm_linux_function_app[%s].site_config.remote_debugging_enabled", [name]),
        "searchLine": common_lib.build_search_line(["resource", "azurerm_linux_function_app", name, "site_config", "remote_debugging_enabled"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "remote_debugging_enabled should be false",
        "keyActualValue": sprintf("Found remote_debugging_enabled = %v", [debugging]),
        "remediation": json.marshal({
            "before": sprintf("remote_debugging_enabled = %v", [debugging]),
            "after": "remote_debugging_enabled = false"
        }),
        "remediationType": "replacement"
    }
}

# Rule for azurerm_linux_function_app_slot
CxPolicy[result] {
    resource := input.document[i].resource.azurerm_linux_function_app_slot[name]
    common_lib.valid_key(resource, "site_config")
    config := object.get(resource, "site_config", "undefined")
    common_lib.valid_key(config, "remote_debugging_enabled")
    debugging := config.remote_debugging_enabled[_]
    debugging

    result := {
        "documentId": input.document[i].id,
        "resourceType": "azurerm_linux_function_app_slot",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("azurerm_linux_function_app_slot[%s].site_config.remote_debugging_enabled", [name]),
        "searchLine": common_lib.build_search_line(["resource", "azurerm_linux_function_app_slot", name, "site_config", "remote_debugging_enabled"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "remote_debugging_enabled should be false",
        "keyActualValue": sprintf("Found remote_debugging_enabled = %v", [debugging]),
        "remediation": json.marshal({
            "before": sprintf("remote_debugging_enabled = %v", [debugging]),
            "after": "remote_debugging_enabled = false"
        }),
        "remediationType": "replacement"
    }
}

# Rule for azurerm_linux_web_app
CxPolicy[result] {
    resource := input.document[i].resource.azurerm_linux_web_app[name]
    common_lib.valid_key(resource, "site_config")
    config := object.get(resource, "site_config", "undefined")
    common_lib.valid_key(config, "remote_debugging_enabled")
    debugging := config.remote_debugging_enabled[_]
    debugging

    result := {
        "documentId": input.document[i].id,
        "resourceType": "azurerm_linux_web_app",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("azurerm_linux_web_app[%s].site_config.remote_debugging_enabled", [name]),
        "searchLine": common_lib.build_search_line(["resource", "azurerm_linux_web_app", name, "site_config", "remote_debugging_enabled"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "remote_debugging_enabled should be false",
        "keyActualValue": sprintf("Found remote_debugging_enabled = %v", [debugging]),
        "remediation": json.marshal({
            "before": sprintf("remote_debugging_enabled = %v", [debugging]),
            "after": "remote_debugging_enabled = false"
        }),
        "remediationType": "replacement"
    }
}

# Rule for azurerm_linux_web_app_slot
CxPolicy[result] {
    resource := input.document[i].resource.azurerm_linux_web_app_slot[name]
    common_lib.valid_key(resource, "site_config")
    config := object.get(resource, "site_config", "undefined")
    common_lib.valid_key(config, "remote_debugging_enabled")
    debugging := config.remote_debugging_enabled[_]
    debugging

    result := {
        "documentId": input.document[i].id,
        "resourceType": "azurerm_linux_web_app_slot",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("azurerm_linux_web_app_slot[%s].site_config.remote_debugging_enabled", [name]),
        "searchLine": common_lib.build_search_line(["resource", "azurerm_linux_web_app_slot", name, "site_config", "remote_debugging_enabled"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "remote_debugging_enabled should be false",
        "keyActualValue": sprintf("Found remote_debugging_enabled = %v", [debugging]),
        "remediation": json.marshal({
            "before": sprintf("remote_debugging_enabled = %v", [debugging]),
            "after": "remote_debugging_enabled = false"
        }),
        "remediationType": "replacement"
    }
}

# Rule for azurerm_windows_function_app
CxPolicy[result] {
    resource := input.document[i].resource.azurerm_windows_function_app[name]
    common_lib.valid_key(resource, "site_config")
    config := object.get(resource, "site_config", "undefined")
    common_lib.valid_key(config, "remote_debugging_enabled")
    debugging := config.remote_debugging_enabled[_]
    debugging

    result := {
        "documentId": input.document[i].id,
        "resourceType": "azurerm_windows_function_app",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("azurerm_windows_function_app[%s].site_config.remote_debugging_enabled", [name]),
        "searchLine": common_lib.build_search_line(["resource", "azurerm_windows_function_app", name, "site_config", "remote_debugging_enabled"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "remote_debugging_enabled should be false",
        "keyActualValue": sprintf("Found remote_debugging_enabled = %v", [debugging]),
        "remediation": json.marshal({
            "before": sprintf("remote_debugging_enabled = %v", [debugging]),
            "after": "remote_debugging_enabled = false"
        }),
        "remediationType": "replacement"
    }
}

# Rule for azurerm_windows_function_app_slot
CxPolicy[result] {
    resource := input.document[i].resource.azurerm_windows_function_app_slot[name]
    common_lib.valid_key(resource, "site_config")
    config := object.get(resource, "site_config", "undefined")
    common_lib.valid_key(config, "remote_debugging_enabled")
    debugging := config.remote_debugging_enabled[_]
    debugging

    result := {
        "documentId": input.document[i].id,
        "resourceType": "azurerm_windows_function_app_slot",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("azurerm_windows_function_app_slot[%s].site_config.remote_debugging_enabled", [name]),
        "searchLine": common_lib.build_search_line(["resource", "azurerm_windows_function_app_slot", name, "site_config", "remote_debugging_enabled"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "remote_debugging_enabled should be false",
        "keyActualValue": sprintf("Found remote_debugging_enabled = %v", [debugging]),
        "remediation": json.marshal({
            "before": sprintf("remote_debugging_enabled = %v", [debugging]),
            "after": "remote_debugging_enabled = false"
        }),
        "remediationType": "replacement"
    }
}

# Rule for azurerm_windows_web_app
CxPolicy[result] {
    resource := input.document[i].resource.azurerm_windows_web_app[name]
    common_lib.valid_key(resource, "site_config")
    config := object.get(resource, "site_config", "undefined")
    common_lib.valid_key(config, "remote_debugging_enabled")
    debugging := config.remote_debugging_enabled[_]
    debugging

    result := {
        "documentId": input.document[i].id,
        "resourceType": "azurerm_windows_web_app",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey":sprintf("azurerm_windows_web_app[%s].site_config.remote_debugging_enabled", [name]),
        "searchLine": common_lib.build_search_line(["resource", "azurerm_windows_web_app", name, "site_config", "remote_debugging_enabled"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "remote_debugging_enabled should be false",
        "keyActualValue": sprintf("Found remote_debugging_enabled = %v", [debugging]),
        "remediation": json.marshal({
            "before": sprintf("remote_debugging_enabled = %v", [debugging]),
            "after": "remote_debugging_enabled = false"
        }),
        "remediationType": "replacement"
    }
}

# Rule for azurerm_windows_web_app_slot
CxPolicy[result] {
    resource := input.document[i].resource.azurerm_windows_web_app_slot[name]
    common_lib.valid_key(resource, "site_config")
    config := object.get(resource, "site_config", "undefined")
    common_lib.valid_key(config, "remote_debugging_enabled")
    debugging := config.remote_debugging_enabled[_]
    debugging

    result := {
        "documentId": input.document[i].id,
        "resourceType": "azurerm_windows_web_app_slot",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("azurerm_windows_web_app_slot[%s].site_config.remote_debugging_enabled", [name]),
        "searchLine": common_lib.build_search_line(["resource", "azurerm_windows_web_app_slot", name, "site_config", "remote_debugging_enabled"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "remote_debugging_enabled should be false",
        "keyActualValue": sprintf("Found remote_debugging_enabled = %v", [debugging]),
        "remediation": json.marshal({
            "before": sprintf("remote_debugging_enabled = %v", [debugging]),
            "after": "remote_debugging_enabled = false"
        }),
        "remediationType": "replacement"
    }
}
