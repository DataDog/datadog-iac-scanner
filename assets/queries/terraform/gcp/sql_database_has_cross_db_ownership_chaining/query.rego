package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
   	settings := input.document[i].resource.google_sql_database_instance[name].settings

    # For each flag in resource.settings.database_flags
    flag := object.get(settings, "database_flags", "")

    flag.name == "cross db ownership chaining"
    flag.value == "on"

	result := {
        "documentId":        input.document[i].id,
        "resourceType":      "google_sql_database_instance",
        "resourceName":      tf_lib.get_resource_name(settings, name),
        "searchKey":         sprintf("google_sql_database_instance[%s].settings.database_flags.cross db ownership chaining.value", [name]),
        "issueType":         "IncorrectValue",
        "keyExpectedValue":  "'settings.database_flags.cross db ownership chaining' should be off",
        "keyActualValue":    "'settings.database_flags.cross db ownership chaining' is on",
        "searchLine":        common_lib.build_search_line(["resource", "google_sql_database_instance", name], ["settings", "database_flags", "cross db ownership chaining", "value"]),
        "remediation":       json.marshal({
                                "before": "on",
                                "after":  "off"
                            }),
        "remediationType":   "replacement",
    }
}
