package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "gcp_compute_disk"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	disk := task[variant]
	ansLib.checkState(disk)

	not common_lib.valid_key(disk, "disk_encryption_key")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(disk, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "gcp_compute_disk.disk_encryption_key should be defined and not null",
		"keyActualValue": "gcp_compute_disk.disk_encryption_key is undefined or null",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	disk := task[variant]
	ansLib.checkState(disk)

	not common_lib.valid_key(disk.disk_encryption_key, "raw_key")
	not common_lib.valid_key(disk.disk_encryption_key, "kms_key_name")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(disk, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.disk_encryption_key", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "gcp_compute_disk.disk_encryption_key.raw_key or gcp_compute_disk.disk_encryption_key.kms_key_name should be defined and not null",
		"keyActualValue": "gcp_compute_disk.disk_encryption_key.raw_key and gcp_compute_disk.disk_encryption_key.kms_key_name are undefined or null",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	disk := task[variant]
	ansLib.checkState(disk)

	key := check_key_empty(disk.disk_encryption_key)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(disk, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.disk_encryption_key.%s", [task.name, variant, key]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("gcp_compute_disk.disk_encryption_key.%s should not be empty", [key]),
		"keyActualValue": sprintf("gcp_compute_disk.disk_encryption_key.%s is empty", [key]),
	}
}

check_key_empty(disk_encryption_key) = key {
	common_lib.valid_key(disk_encryption_key, "raw_key")
	disk_encryption_key.raw_key == ""
	key := "raw_key"
} else = key {
	common_lib.valid_key(disk_encryption_key, "kms_key_name")
	disk_encryption_key.kms_key_name == ""
	key := "kms_key_name"
}
