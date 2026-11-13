/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfcorpus

import (
	"fmt"
	"strings"
)

// buildCell fills in the Terraform files of a value cell. The sink writes its
// probe attribute through the cell's indirection; the unknown neighbor and
// the value's source add the blocks they need.
func buildCell(c Cell) Cell {
	c.files = map[string]string{}
	if c.Source == "merged" {
		c.Variant = "objmerged"
	} else if objectSource(c) {
		c.Variant = "objmap"
	}
	var sinkAttrs []string
	var extras []string // whole extra blocks and files, appended after the sink

	literal := shapes[c.Shape].fire
	if !c.Fire {
		literal = shapes[c.Shape].noFire
	}
	// srcExpr is the expression that yields the read value from the cell's
	// source; srcFiles are the files that source needs. An object source
	// holds the scalar firing value in its probe_source attribute, whatever
	// the cell's shape: the read value is the object itself.
	srcLiteral := literal
	if objectSource(c) {
		srcLiteral = `"fire"`
		if !c.Fire {
			srcLiteral = `"safe"`
		}
	}
	if objectSource(c) && !c.Fire {
		// The non-firing object holds two attributes: no probe read can
		// mistake it for the firing single-attribute object.
		switch c.Source {
		case "lookalike":
			srcLiteral = `"safe", extra = "x"`
		case "resource_object":
			srcLiteral = `"safe"
  extra = "x"`
		}
	}
	srcExpr, srcFiles, _ := cellSource(c, srcLiteral)
	for name, content := range srcFiles {
		c.files[name] = content
	}

	// probeExpr is what the sink's probe attribute is written with.
	probeExpr := srcExpr
	needUnset := false
	switch c.Indirection {
	case "":
		probeExpr = literal
	case "variable":
		c.files["vars.tf"] = fmt.Sprintf("variable \"val\" {\n  default = %s\n}\n", literal)
		probeExpr = "var.val"
	case "local":
		// A root may already declare locals for its source; locals blocks
		// repeat, so append.
		c.files["locals.tf"] += fmt.Sprintf("\nlocals {\n  val = %s\n}\n", srcExpr)
		probeExpr = "local.val"
	case "module_io":
		c.files["mod/main.tf"] = "variable \"in_val\" {}\n"
		if c.Neighbor == "module_empty_arg" {
			c.files["mod/main.tf"] += "variable \"extraArg\" {}\n"
		}
		c.files["mod/main.tf"] += "\noutput \"out_val\" {\n  value = var.in_val\n}\n"
		if c.Neighbor == "module_empty_arg" {
			// The empty instance answers unknown; a plain object errors
			// into the fallback. The third sink observes it.
			c.files["mod/main.tf"] += "\noutput \"out_extra\" {\n  value = try(var.extraArg.anything, \"fire\")\n}\n"
			c.files["sink3.tf"] = renderSinkNamed("resource", "sink3", []string{"probe = module.m.out_extra"})
		}
		extraArg := ""
		if c.Neighbor == "module_empty_arg" {
			extraArg = "  extraArg = aws_instance.empty\n"
		}
		call := fmt.Sprintf("module \"m\" {\n  source = \"./mod\"\n  in_val = %s\n%s}\n", srcExpr, extraArg)
		// The same module called with the resource object and with the
		// lookalike object in one root exercises the per-root caches: two
		// arguments that evaluate equal but do not carry the same marks. The
		// second call's sink reads the output that tells an instance object
		// from a plain one - an instance answers unknown, a plain object
		// errors into the fallback - so a cache that mixes the two
		// evaluations up shows up as a lost finding on sink2, and a third
		// sink observes the first call's output the same way.
		if c.Source == "resource_object" || c.Source == "lookalike" {
			fallbackObj := `{ probe_source = "fire" }`
			if !c.Fire {
				fallbackObj = `{ probe_source = "safe", extra = "x" }`
			}
			c.files["mod/main.tf"] += "\noutput \"out_missing\" {\n  value = try(var.in_val.missing, " + fallbackObj + ")\n}\n"
			// The observed call passes the resource object; the second
			// call passes an ordinary object of the same value. Both are
			// declared: the resource in src.tf by cellSource, the ordinary
			// object here.
			other := "local.src"
			decl := "\nlocals {\n  src = { probe_source = %s }\n}\n"
			decl = fmt.Sprintf(decl, srcLiteral)
			if c.Source == "lookalike" {
				other = "aws_instance.src"
				decl = fmt.Sprintf("\nresource \"aws_instance\" \"src\" {\n  probe_source = %s\n}\n", strings.ReplaceAll(srcLiteral, ", extra = ", "\n  extra = "))
			}
			call += decl + fmt.Sprintf("module \"m2\" {\n  source = \"./mod\"\n  in_val = %s\n}\n\nresource \"aws_s3_bucket\" \"sink2\" {\n  probe = module.m2.out_missing\n}\n", other)
			call += "\nresource \"aws_s3_bucket\" \"sink4\" {\n  probe = module.m.out_missing\n}\n"
			if c.Source == "lookalike" {
				// The observed call's input is the plain lookalike object:
				// its missing-attribute output resolves to the fallback, so
				// sink4 fires like the sink does.
				c.Sinks = 2
			}
			if c.Source == "resource_object" {
				// The second call's input is the plain object: its
				// missing-attribute output resolves to the fallback, so
				// sink2 fires like the sink does.
				c.Sinks = 2
			}
		}
		c.files["main.tf"] = call
		probeExpr = "module.m.out_val"
	case "module_sink":
		extraVar := ""
		if c.Neighbor == "module_empty_arg" {
			extraVar = "variable \"extraArg\" {}\n"
		}
		c.files["mod/main.tf"] = extraVar + fmt.Sprintf("variable \"in_val\" {\n  default = %s\n}\n\nresource \"aws_s3_bucket\" \"sink\" {\n  probe = var.in_val\n}\n", literal)
		if c.Neighbor == "module_empty_arg" {
			c.files["mod/main.tf"] += "\noutput \"out_extra\" {\n  value = try(var.extraArg.anything, \"fire\")\n}\n"
			c.files["sink3.tf"] = renderSinkNamed("resource", "sink3", []string{"probe = module.m.out_extra"})
		}
		extraArg := ""
		if c.Neighbor == "module_empty_arg" {
			extraArg = "  extraArg = aws_instance.empty\n"
		}
		c.files["main.tf"] = "module \"m\" {\n  source = \"./mod\"\n" + extraArg + "}\n"
		probeExpr = "" // the sink lives in the module
	case "data_source":
		dataArg := literal
		if c.Source == "resource_attr" {
			dataArg = "aws_instance.src.probe_source"
		}
		c.files["data.tf"] = fmt.Sprintf("data \"probe_data\" \"src\" {\n  value = %s\n}\n\nlocals {\n  val = data.probe_data.src.value\n}\n", dataArg)
		probeExpr = "local.val"
	case "data_count":
		// resource -> local -> data, with the sink count driven from the
		// data as well: a stale local during the count expansion shows up
		// as a wrong probe value or a lost instance.
		c.files["src.tf"] = fmt.Sprintf("resource \"aws_instance\" \"src\" {\n  probe_source = %s\n}\n", literal)
		c.files["data.tf"] = "locals {\n  val = aws_instance.src.probe_source\n}\n\n" +
			"data \"probe_data\" \"src\" {\n  value = local.val\n  num = 1\n}\n"
		sinkAttrs = append(sinkAttrs, "count = data.probe_data.src.num", "probe = data.probe_data.src.value")
		c.Keys = []string{"sink[0]"}
		probeExpr = ""
	case "try":
		// try keeps its first argument when it reads, and takes the fallback
		// when reading errors: the fallback is the cell's value.
		fallback := literal
		switch c.Source {
		case "written":
			// Reading an attribute the object does not have is an error, so
			// try takes the fallback.
			c.files["locals.tf"] = "locals {\n  missing = {}\n}\n"
			probeExpr = fmt.Sprintf("try(local.missing.attr, %s)", fallback)
		case "resource_attr":
			// A computed attribute is unknown; try keeps the unknown, which
			// is what Terraform does with an unknown first argument.
			probeExpr = "try(aws_instance.src.probe_source, " + fallback + ")"
		case "resource_object", "lookalike":
			// The whole object: an ordinary object equal to a resource's
			// configured value, with the resource present, is exactly what
			// the try returns.
			c.files["src.tf"] = fmt.Sprintf("resource \"aws_instance\" \"src\" {\n  probe_source = %s\n}\n", strings.ReplaceAll(srcLiteral, ", extra = ", "\n  extra = "))
			if c.Source == "lookalike" {
				c.files["locals.tf"] = fmt.Sprintf("locals {\n  src = { probe_source = %s }\n}\n", srcLiteral)
				probeExpr = fmt.Sprintf("try(local.src, %s)", fallback)
			} else {
				probeExpr = fmt.Sprintf("try(aws_instance.src, %s)", fallback)
			}
		}
	case "coalesce":
		probeExpr = fmt.Sprintf("coalesce(null, %s)", literal)
	case "conditional":
		fire, noFire := shapes[c.Shape].fire, shapes[c.Shape].noFire
		if !c.Fire {
			fire, noFire = noFire, fire
		}
		if c.Source == "resource_attr" {
			probeExpr = fmt.Sprintf("aws_instance.src.flag ? %s : %s", fire, noFire)
			// The source resource already exists; add the flag to it.
			if prev, ok := c.files["src.tf"]; ok {
				c.files["src.tf"] = strings.Replace(prev, "\n}", "\n  flag = true\n}", 1)
			} else {
				c.files["srcflag.tf"] = "resource \"aws_instance\" \"src\" {\n  flag = true\n}\n"
			}
		} else {
			probeExpr = fmt.Sprintf("true ? %s : %s", fire, noFire)
		}
	case "for_expr":
		switch c.Shape {
		case "map":
			probeExpr = fmt.Sprintf("{ for k, v in %s : k => v }", srcExpr)
		default: // list and set: the projected value is an array either way
			probeExpr = fmt.Sprintf("[ for v in %s : v ]", srcExpr)
		}
	case "for_each":
		value := shapes["scalar"].fire
		if !c.Fire {
			value = shapes["scalar"].noFire
		}
		sinkAttrs = append(sinkAttrs, "for_each = toset(["+value+"])", "probe = each.value")
		probeExpr = ""
	case "count":
		defaults := `["fire"]`
		if !c.Fire {
			defaults = `["safe", "x"]`
			c.Keys = []string{"sink[0]", "sink[1]"}
		} else {
			c.Keys = []string{"sink[0]"}
		}
		c.files["vars.tf"] = fmt.Sprintf("variable \"vals\" {\n  default = %s\n}\n", defaults)
		sinkAttrs = append(sinkAttrs, "count = length(var.vals)", "probe = "+literal)
		probeExpr = ""
	case "splat":
		// The splat result is the list; its element is the scalar value. A
		// non-firing splat yields two elements, so a count read cannot
		// mistake it for the firing single-element list.
		item := shapes["scalar"].fire
		if !c.Fire {
			item = shapes["scalar"].noFire
		}
		items := fmt.Sprintf("[{ attr = %s }]", item)
		if !c.Fire {
			items = fmt.Sprintf("[{ attr = %s }, { attr = \"x\" }]", item)
		}
		if c.Source == "resource_attr" {
			probeExpr = "aws_instance.src.items[*].attr"
			if prev, ok := c.files["src.tf"]; ok {
				c.files["src.tf"] = strings.Replace(prev, "  probe_source = ", "  items = "+items+"\n  probe_source = ", 1)
			}
		} else {
			probeExpr = "local.items[*].attr"
			c.files["locals.tf"] = fmt.Sprintf("locals {\n  items = %s\n}\n", items)
		}
	case "nested":
		switch c.Shape {
		case "nested":
			inner := "local.obj.inner"
			if c.Source == "resource_attr" {
				inner = "aws_instance.src.probe_source"
			}
			probeExpr = inner
			if c.Source == "written" {
				c.files["locals.tf"] = fmt.Sprintf("locals {\n  obj = { inner = %s }\n}\n", literal)
			}
		default: // scalar through an object path
			attr := shapes["scalar"].fire
			if !c.Fire {
				attr = shapes["scalar"].noFire
			}
			if c.Source == "resource_object" {
				// The whole source object is not the read value here: the
				// probe reads one nested attribute of it.
				delete(c.files, "src.tf")
				c.files["src.tf"] = fmt.Sprintf("resource \"aws_instance\" \"src\" {\n  deep = { attr = %s }\n}\n", attr)
				probeExpr = "aws_instance.src.deep.attr"
			} else {
				probeExpr = "local.obj.deep.attr"
				c.files["locals.tf"] = fmt.Sprintf("locals {\n  obj = { deep = { attr = %s } }\n}\n", attr)
			}
		}
	default:
		panic("unknown indirection " + c.Indirection)
	}

	if probeExpr != "" {
		sinkAttrs = append(sinkAttrs, "probe = "+probeExpr)
	}
	sinkAttrs = append(sinkAttrs, neighborAttrs(c, &needUnset, &extras)...)
	if needUnset {
		c.files["unset.tf"] = "variable \"unset_value\" {}\n"
	}
	// The sink of a module_sink cell lives in the module's own file; the
	// root declares no sink block of its own.
	if c.Indirection != "module_sink" {
		c.files["sink.tf"] = renderSink(c.SinkKind, sinkAttrs)
	}
	for _, extra := range extras {
		c.files["neighbor.tf"] += extra
	}
	return c
}

// buildLiteral fills the files of an oracle cell: the value written directly
// on the sink, no indirection, no unknown neighbor. An object-source cell
// resolves to the resource's attributes, so its oracle writes those
// attributes as the literal.
func buildLiteral(c *Cell) {
	if c.Variant == "objmap" || c.Variant == "objmerged" {
		value := `"fire"`
		if !c.Fire {
			value = `"safe"`
		}
		literal := fmt.Sprintf("{ probe_source = %s }", value)
		if c.Variant == "objmerged" {
			literal = fmt.Sprintf("{ probe_source = %s, label = \"x\" }", value)
		}
		if !c.Fire {
			// The cell's non-firing object holds two attributes; the
			// oracle must match it.
			literal = fmt.Sprintf("{ probe_source = %s, extra = \"x\" }", value)
		}
		files := map[string]string{
			"sink.tf": renderSink("resource", []string{"probe = " + literal}),
		}
		if c.Sinks == 2 {
			second := "sink2"
			if c.Source == "lookalike" {
				second = "sink4"
			}
			files[second+".tf"] = renderSinkNamed("resource", second, []string{"probe = " + literal})
		}
		c.files = files
		return
	}
	literal := shapes[c.Shape].fire
	if !c.Fire {
		literal = shapes[c.Shape].noFire
	}
	files := map[string]string{
		"sink.tf": renderSink("resource", []string{"probe = " + literal}),
	}
	if c.Sinks == 2 {
		second := "sink2"
		if c.Source == "lookalike" {
			second = "sink4"
		}
		files[second+".tf"] = renderSinkNamed("resource", second, []string{"probe = " + literal})
	}
	c.files = files
}

// cellSource returns the expression yielding the read value from the cell's
// source, the files that source needs, and whether the projected value is an
// object built from a resource's attributes.
func cellSource(c Cell, literal string) (expr string, files map[string]string, object bool) {
	files = map[string]string{}
	switch c.Source {
	case "", "written":
		return literal, files, false
	case "resource_attr":
		files["src.tf"] = fmt.Sprintf("resource \"aws_instance\" \"src\" {\n  probe_source = %s\n}\n", literal)
		return "aws_instance.src.probe_source", files, false
	case "resource_object":
		files["src.tf"] = fmt.Sprintf("resource \"aws_instance\" \"src\" {\n  probe_source = %s\n}\n", literal)
		return "aws_instance.src", files, true
	case "lookalike":
		files["locals.tf"] = fmt.Sprintf("locals {\n  src = { probe_source = %s }\n}\n", literal)
		return "local.src", files, true
	case "merged":
		files["src.tf"] = fmt.Sprintf("resource \"aws_instance\" \"src\" {\n  probe_source = %s\n}\n", literal)
		return "merge(aws_instance.src, { label = \"x\" })", files, true
	}
	panic("unknown source " + c.Source)
}

// neighborAttrs returns the sink attributes and extra blocks an unknown
// neighbor needs. The neighbor never feeds the probe attribute.
func neighborAttrs(c Cell, needUnset *bool, extras *[]string) []string {
	switch c.Neighbor {
	case "", "none":
		return nil
	case "same_block":
		*needUnset = true
		return []string{"unrelated = var.unset_value"}
	case "sibling":
		*needUnset = true
		*extras = append(*extras, "resource \"aws_instance\" \"nbr\" {\n  for_each = var.unset_value\n  probe_source = \"nbr\"\n}\n\n")
		return nil
	case "related":
		*needUnset = true
		*extras = append(*extras, "resource \"aws_s3_bucket_versioning\" \"rel\" {\n  bucket = aws_s3_bucket.sink.id\n  versioning_configuration {\n    status = var.unset_value\n  }\n}\n\n")
		return nil
	case "computed":
		// The computed reference reads a provider-computed attribute of the
		// source resource when the source already declares one.
		if !objectSource(c) && c.Source != "resource_attr" {
			*extras = append(*extras, "resource \"aws_instance\" \"src\" {\n  probe_source = \"x\"\n}\n\n")
		}
		return []string{"computed_ref = aws_instance.src.id"}
	case "module_arg":
		*needUnset = true
		*extras = append(*extras, "module \"mUnknown\" {\n  source = \"./mod\"\n  in_val = var.unset_value\n}\n\n")
		return nil
	case "module_empty_arg":
		// The empty resource object is a second input of the observed
		// module call; the call wiring adds it where the call is built.
		*extras = append(*extras, "resource \"aws_instance\" \"empty\" {}\n\n")
		return nil
	}
	panic("unknown neighbor " + c.Neighbor)
}

// renderSink writes the sink block of a cell.
func renderSink(kind string, attrs []string) string {
	return renderSinkNamed(kind, "sink", attrs)
}

// renderSinkNamed writes a sink block with the given label.
func renderSinkNamed(kind, name string, attrs []string) string {
	head := map[string]string{
		"resource":  fmt.Sprintf("resource %q %q {", SinkType, name),
		"data":      fmt.Sprintf("data %q %q {", SinkType, name),
		"ephemeral": fmt.Sprintf("ephemeral %q %q {", SinkType, name),
	}[kind]
	if head == "" {
		panic("unknown sink kind " + kind)
	}
	body := strings.ReplaceAll(strings.Join(attrs, "\n"), "\n", "\n  ")
	return head + "\n  " + body + "\n}\n"
}

// buildExpansion fills the files of a parity cell: one sink per expansion,
// its probe attribute written literally.
func buildExpansion(c Cell) Cell {
	c.files = map[string]string{}
	literal := shapes[c.Shape].fire
	if !c.Fire {
		literal = shapes[c.Shape].noFire
	}
	name := "sink"
	switch c.Expansion {
	case "none":
		c.files["sink.tf"] = renderSink(c.SinkKind, []string{"probe = " + literal})
	case "count1", "count3", "count258":
		n := map[string]int{"count1": 1, "count3": 3, "count258": 258}[c.Expansion]
		c.files["sink.tf"] = renderSink(c.SinkKind, []string{fmt.Sprintf("count = %d", n), "probe = " + literal})
	case "foreach_map":
		value := shapes["scalar"].fire
		if !c.Fire {
			value = shapes["scalar"].noFire
		}
		c.files["sink.tf"] = renderSink(c.SinkKind, []string{
			"for_each = { one = " + value + ", two = " + value + " }", "probe = each.value"})
	case "foreach_set", "foreach_set3":
		keys := `["k"]`
		if c.Expansion == "foreach_set3" {
			keys = `["k1", "k2", "k3"]`
		}
		c.files["sink.tf"] = renderSink(c.SinkKind, []string{
			"for_each = toset(" + keys + ")", "probe = " + literal})
	case "module_count", "module_count3", "module_foreach", "nested":
		c.Keys = []string{name}
		c.files["mod/main.tf"] = renderSink("resource", []string{"probe = " + literal})
		call := "module \"m\" {\n  source = \"./mod\"\n"
		switch c.Expansion {
		case "module_count":
			call += "  count = 1\n"
		case "module_count3":
			call += "  count = 3\n"
		case "module_foreach":
			call += "  for_each = { one = \"a\", two = \"b\" }\n"
		case "nested":
			c.files["mod/inner/main.tf"] = renderSink("resource", []string{"probe = " + literal})
			c.files["mod/main.tf"] = "module \"inner\" {\n  source = \"../inner\"\n}\n"
		}
		call += "}\n"
		c.files["main.tf"] = call
	default:
		panic("unknown expansion " + c.Expansion)
	}
	return c
}
