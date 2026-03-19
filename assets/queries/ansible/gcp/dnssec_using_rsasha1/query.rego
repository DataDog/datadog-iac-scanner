package Cx

import data.generic.ansible as ansLib

canonical := "gcp_dns_managed_zone"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	dns := task[variant]
	ansLib.checkState(dns)

	lower(dns.dnssec_config.defaultKeySpecs.algorithm) == "rsasha1"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(dns, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.dnssec_config.defaultKeySpecs.algorithm", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_dns_managed_zone.dnssec_config.defaultKeySpecs.algorithm should not equal to 'rsasha1'",
		"keyActualValue": "gcp_dns_managed_zone.dnssec_config.defaultKeySpecs.algorithm is equal to 'rsasha1'",
	}
}
