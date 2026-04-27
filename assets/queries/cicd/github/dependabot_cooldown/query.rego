package Cx

import data.generic.common as common_lib
import data.generic.cicd as cicd_lib

# Default minimum cooldown days
default_min_cooldown_days := 7

# Check for missing cooldown configuration entirely
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"

	# Iterate through each update configuration
	update := doc.updates[idx]

	# Check if cooldown is missing
	not update.cooldown

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("updates[%d]", [idx]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "Dependabot update should have cooldown configuration",
		"keyActualValue": "Missing cooldown configuration",
		"searchLine": common_lib.build_search_line(["updates", idx], []),
		"resourceType": "dependabot_update",
		"resourceName": sprintf("update-%d", [idx])
	}
}

# Check for cooldown block present but missing default-days
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"

	# Iterate through each update configuration
	update := doc.updates[idx]

	# Check if cooldown exists but default-days is missing
	cooldown := update.cooldown
	not cooldown["default-days"]

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("updates[%d].cooldown", [idx]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "Cooldown configuration should have default-days set",
		"keyActualValue": "No default-days configured in cooldown",
		"searchLine": common_lib.build_search_line(["updates", idx, "cooldown"], []),
		"resourceType": "dependabot_update",
		"resourceName": sprintf("update-%d", [idx])
	}
}

# Check for insufficient default-days value
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"

	# Iterate through each update configuration
	update := doc.updates[idx]

	# Check if cooldown exists and default-days is less than threshold
	cooldown := update.cooldown
	default_days := cooldown["default-days"]

	# Check if default-days is less than minimum (7 days)
	default_days < default_min_cooldown_days

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("updates[%d].cooldown.default-days={{%d}}", [idx, default_days]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("Cooldown default-days should be at least %d", [default_min_cooldown_days]),
		"keyActualValue": sprintf("Insufficient default-days configured: %d (less than %d)", [default_days, default_min_cooldown_days]),
		"searchLine": common_lib.build_search_line(["updates", idx, "cooldown", "default-days"], []),
		"resourceType": "dependabot_update",
		"resourceName": sprintf("update-%d", [idx])
	}
}
