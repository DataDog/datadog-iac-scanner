package converter_test

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/converter"
	"github.com/hashicorp/hcl/v2/hclparse"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

func TestTosetForEachInDynamicBlock(t *testing.T) {
	src := []byte(`resource "google_sql_database_instance" "x" {
  settings {
    dynamic "ip_configuration" {
      for_each = toset(["private"])
      content {
        ipv4_enabled = false
        private_network = "net"
      }
    }
  }
}`)
	parser := hclparse.NewParser()
	file, diags := parser.ParseHCL(src, "test.tf")
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	doc, err := converter.DefaultConverted(context.Background(), file, nil)
	if err != nil {
		t.Fatal(err)
	}
	resource := doc["resource"].(model.Document)["google_sql_database_instance"].(model.Document)["x"].(model.Document)
	settings := resource["settings"].(model.Document)
	dynamic := settings["dynamic"].(model.Document)
	ipConfiguration := dynamic["ip_configuration"].(model.Document)
	forEachVal, ok := ipConfiguration["for_each"].(ctyjson.SimpleJSONValue)
	if !ok {
		t.Fatalf("for_each = %#v (%T), want ctyjson.SimpleJSONValue", ipConfiguration["for_each"], ipConfiguration["for_each"])
	}
	if forEachVal.Value.LengthInt() != 1 {
		t.Fatalf("for_each len = %d, want 1", forEachVal.Value.LengthInt())
	}
}
