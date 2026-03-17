package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

# Canonicals for package installer modules (replaces ansLib.installer_modules)
installer_canonicals := {
	"apk", "apt", "bower", "bundler", "dnf", "easy_install", "gem", "homebrew",
	"jenkins_plugin", "npm", "openbsd_pkg", "package", "pacman", "pear", "pip",
	"pkg5", "pkgutil", "portage", "slackpkg", "sorcery", "swdepot", "win_chocolatey",
	"yarn", "yum", "zypper",
}

CxPolicy[result] {
	some canonical
	installer_canonicals[canonical]
	task := ansLib.tasks[id][_]
	variant := ansLib.get_variants(canonical)[_]
	package_installer := task[variant]
	ansLib.checkState(package_installer)

	not common_lib.valid_key(package_installer, "version")
	not common_lib.valid_key(package_installer, "update_only")
	package_installer.state == "latest"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(package_installer, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.state", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "State's task when installing a package should not be defined as 'latest' or should have set 'update_only' to 'true'",
		"keyActualValue": "State's task is set to 'latest'",
	}
}

CxPolicy[result] {
	some canonical
	installer_canonicals[canonical]
	task := ansLib.tasks[id][_]
	variant := ansLib.get_variants(canonical)[_]
	package_installer := task[variant]
	ansLib.checkState(package_installer)

	not common_lib.valid_key(package_installer, "version")
	package_installer.update_only == false
	package_installer.state == "latest"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(package_installer, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.state", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "State's task when installing a package should not be defined as 'latest' or should have set 'update_only' to 'true'",
		"keyActualValue": "State's task is set to 'latest'",
	}
}
