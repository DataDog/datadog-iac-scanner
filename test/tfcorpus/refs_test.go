package tfcorpus

import "testing"

// TestCheckRefsScopesAndStructure checks the reference validator's
// scoping and its structure awareness on hand-built fixtures.
func TestCheckRefsScopesAndStructure(t *testing.T) {
	nl := "\n"
	q := "\""
	// A root that reads a local no root file declares, while a child
	// module declares it: the child's declaration must not satisfy the
	// root's reference.
	cell := Cell{files: map[string]string{
		"main.tf":     "locals {" + nl + "  missing = local.undeclared" + nl + "}" + nl,
		"mod/main.tf": "locals {" + nl + "  undeclared = " + q + "x" + q + nl + "}" + nl,
	}}
	if err := checkRefs(cell); err == nil {
		t.Fatal("the child module's declaration satisfied the root's reference")
	}
	// A nested object inside locals: its keys are not declarations, and a
	// local declared after the nested object is still found.
	cell2 := Cell{files: map[string]string{
		"main.tf": "locals {" + nl + "  src = {" + nl + "    hidden = " + q + "fire" + q + nl + "  }" + nl + "  later = " + q + "x" + q + nl + "}" + nl + nl + "resource \"aws_s3_bucket\" \"sink\" {" + nl + "  probe = local.src.hidden" + nl + "}" + nl,
	}}
	if err := checkRefs(cell2); err != nil {
		t.Fatalf("a nested-object key read as a declaration, or a local after a nested object was missed: %v", err)
	}
	// Reading a local that truly is nowhere fails.
	cell3 := Cell{files: map[string]string{
		"main.tf": "resource \"aws_s3_bucket\" \"sink\" {" + nl + "  probe = local.nope" + nl + "}" + nl,
	}}
	if err := checkRefs(cell3); err == nil {
		t.Fatal("an undeclared local passed")
	}
	// A variable read in a module directory resolves against that
	// directory's own declaration.
	cell4 := Cell{files: map[string]string{
		"mod/main.tf": "variable \"in_val\" {}" + nl + nl + "resource \"aws_s3_bucket\" \"sink\" {" + nl + "  probe = var.in_val" + nl + "}" + nl,
	}}
	if err := checkRefs(cell4); err != nil {
		t.Fatalf("a module-scoped variable read failed: %v", err)
	}
	// The same variable read at the root with the declaration only in the
	// module fails.
	cell5 := Cell{files: map[string]string{
		"main.tf":     "resource \"aws_s3_bucket\" \"sink\" {" + nl + "  probe = var.in_val" + nl + "}" + nl,
		"mod/main.tf": "variable \"in_val\" {}" + nl,
	}}
	if err := checkRefs(cell5); err == nil {
		t.Fatal("the module's declaration satisfied the root's variable read")
	}
}
