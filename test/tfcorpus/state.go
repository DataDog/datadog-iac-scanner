/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfcorpus

// StateCell is one attribute-state configuration: a sink block whose
// attribute is written in a given state (known, wholly unknown, a partial
// template, ...) at a given placement (top level, nested block, ...).
//
// The projections must stay faithful to the model, so a state cell carries no
// expected values of its own: the walk derives what is written from the
// model, and checks both projections against it.
type StateCell struct {
	// State is how the attribute is written.
	State string
	// Placement is where in the block it is written.
	Placement string
	// Absent lists the paths a state cell declares as never written (the
	// absent states), so the projection walk can require them to stay
	// absent in both projections.
	Absent []string
	// files are the Terraform files of the root.
	files map[string]string
}

// Name identifies a state cell.
func (c StateCell) Name() string {
	return "state=" + c.State + "/placement=" + c.Placement
}

// Repro returns the Terraform files of the cell.
func (c StateCell) Repro() string {
	out := ""
	for name, content := range c.files {
		out += "// " + name + "\n" + content + "\n"
	}
	return out
}

// stateExpr is the value expression of each state: what `attr = ...` holds.
var stateExpr = map[string]string{
	"known":    `"value"`,
	"unknown":  "var.unset",
	"template": `"pre-${var.unset}-post"`,
	"json":     `jsonencode({ k = var.unset })`,
	"computed": "aws_instance.src.id",
	"null":     "null",
}

// StateGrid generates the attribute-state cells. Every cell declares one sink
// of the value grid's sink type; the walk checks the projections of the cell
// against the model it was evaluated from.
func StateGrid() []StateCell {
	rows := []struct{ state, placement string }{
		{"known", "top"},
		{"known", "nested"},
		{"known", "instance"},
		{"known", "module"},
		{"unknown", "top"},
		{"unknown", "nested"},
		{"unknown", "instance"},
		{"unknown", "module"},
		{"template", "top"},
		{"template", "nested"},
		{"json", "top"},
		{"computed", "top"},
		{"null", "top"},
		{"null", "nested"},
		{"absent", "top"},
		{"absent", "nested"},
		{"unknown_count", "sink"},
		{"unknown_dynamic", "sink"},
		{"known_dynamic", "sink"},
	}
	cells := make([]StateCell, 0, len(rows))
	for _, row := range rows {
		cells = append(cells, buildState(row.state, row.placement))
	}
	return cells
}

// buildState writes the files of one state cell.
func buildState(state, placement string) StateCell {
	c := StateCell{State: state, Placement: placement, files: map[string]string{}}
	attr := func(expr string) string {
		switch placement {
		case "top":
			return "attr = " + expr
		case "nested":
			return "settings {\n    attr = " + expr + "\n  }"
		case "instance":
			return "attr = " + expr
		case "module":
			return "attr = " + expr
		}
		panic("unknown placement " + placement)
	}
	switch state {
	case "known", "unknown", "template", "json", "computed", "null":
		c.files["unset.tf"] = "variable \"unset\" {}\n\nresource \"aws_instance\" \"src\" {}\n"
		expr := stateExpr[state]
		if placement == "instance" && state == "known" {
			// The known state keeps one value per instance; every other
			// state keeps its own expression, so an unknown instance
			// really reads an unknown value.
			expr = "each.value"
		}
		line := attr(expr)
		c.writeSink(line)
	case "absent":
		switch placement {
		case "top":
			c.writeSink("other = \"x\"")
			c.Absent = []string{"attr"}
		case "nested":
			c.writeSink("settings {\n    other = \"x\"\n  }")
			c.Absent = []string{"settings.0.attr"}
		}
	case "unknown_count":
		c.files["unset.tf"] = "variable \"unset\" {}\n"
		c.files["sink.tf"] = renderSink("resource", []string{"count = var.unset", "probe = \"x\""})
	case "unknown_dynamic":
		c.files["unset.tf"] = "variable \"unset\" {}\n"
		c.files["sink.tf"] = renderSink("resource", []string{
			"dynamic \"d\" {\n    for_each = var.unset\n    content {\n      inner = d.value\n    }\n  }"})
	case "known_dynamic":
		c.files["sink.tf"] = renderSink("resource", []string{
			`dynamic "d" {
    for_each = ["one", "two"]
    content {
      inner = d.value
    }
  }`})
	default:
		panic("unknown state " + state)
	}
	if placement == "instance" {
		// The state sits on each instance of a known for_each expansion.
		body := c.files["sink.tf"]
		c.files["sink.tf"] = strings_replaceForEach(body)
	}
	if placement == "module" {
		c.files["mod/main.tf"] = "variable \"in\" {}\n\n" + renderSink("resource", []string{"attr = var.in"})
		delete(c.files, "sink.tf")
		c.files["main.tf"] = "module \"m\" {\n  source = \"./mod\"\n  in = " + inValue(state) + "\n}\n"
	}
	return c
}

// inValue passes the state's value into a module call.
func inValue(state string) string {
	switch state {
	case "unknown":
		return "var.unset"
	case "template":
		return `"pre-${var.unset}-post"`
	case "json":
		return `jsonencode({ k = var.unset })`
	default:
		return stateExpr[state]
	}
}

// strings_replaceForEach adds a known for_each with one value per instance
// to the sink block of a state cell, so the attribute sits on every
// instance and the instances do not hold the same value.
func strings_replaceForEach(body string) string {
	const head = "resource \"aws_s3_bucket\" \"sink\" {"
	return head + "\n  for_each = { one = \"x\", two = \"y\" }\n" + body[len(head):]
}

// writeSink writes the sink block of a state cell with the given attribute
// lines.
func (c *StateCell) writeSink(attrs ...string) {
	lines := make([]string, 0, len(attrs))
	for _, a := range attrs {
		lines = append(lines, strings_indent(a))
	}
	c.files["sink.tf"] = renderSink("resource", lines)
}

// strings_indent indents every line of a block body one level.
func strings_indent(s string) string {
	return "  " + s
}
