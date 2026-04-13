package generic.cicd

dangerous_triggers = ["pull_request_target", "workflow_run"]

# Check if workflow has dangerous triggers
has_dangerous_trigger(doc) {
	trigger := doc.on
	trigger == dangerous_triggers[_]
}

has_dangerous_trigger(doc) {
	trigger := doc.on[_]
	trigger == dangerous_triggers[_]
}

has_dangerous_trigger(doc) {
	doc.on[trigger]
	trigger == dangerous_triggers[_]
}
