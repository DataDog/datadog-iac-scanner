package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

# Check if port is exactly equal to target (no dash present)
port_exact(ports, target) {
    p := ports[_]
    not contains(p, "-")
    to_number(p) == target
}

# Check if a port range includes the target
port_range(ports, target) {
    p := ports[_]
    contains(p, "-")
    parts := split(p, "-")
    count(parts) == 2
    from := to_number(parts[0])
    to := to_number(parts[1])
    from <= target
    target <= to
}

# Determine if the target port is allowed by any entry in ports
port_allowed(ports, target) {
    port_exact(ports, target)
} else {
    port_range(ports, target)
}

CxPolicy[result] {
    resource := input.document[i].resource.google_compute_firewall[name]
    common_lib.valid_key(resource, "allow")
    allowBlocks := common_lib.as_array(resource.allow)

    # Check if any allow block permits TCP on port 3306.
    ab := allowBlocks[_]
    common_lib.valid_key(ab, "protocol")
    ab.protocol == "tcp"
    common_lib.valid_key(ab, "ports")
    ports := common_lib.as_array(ab.ports)
    port_allowed(ports, 3306)

    common_lib.valid_key(resource, "source_ranges")
    resource.source_ranges[_] == "0.0.0.0/0"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "google_compute_firewall",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("google_compute_firewall[{{%s}}].source_ranges", [name]),
        "searchLine": common_lib.build_search_line(["resource", "google_compute_firewall", name, "source_ranges"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "google_compute_firewall should not allow unrestricted ingress on port 3306",
        "keyActualValue": "google_compute_firewall allows ingress from 0.0.0.0/0 on port 3306",
        "remediation": json.marshal({
            "before": "source_ranges = [\"0.0.0.0/0\"]",
            "after": "source_ranges = [\"<restricted_ip_range>\"]"
        }),
        "remediationType": "replacement"
    }
}
